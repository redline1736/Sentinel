#include "../../global.h"
#include <unistd.h>
#include <limits.h>
#include <cjson/cJSON.h>

#include "../../http/http.h"
#include "../sock/sock.h"
#include "gq.h"

#define SOCK_PATH "/tmp/sentinel.sock"

/* ------------------------------------------------------------------
 * Data structures
 * ------------------------------------------------------------------ */

typedef struct {
    char *name;
    char *type_string;
} ArgInfo;

typedef struct {
    char *name;
    ArgInfo *args;
    int num_args;
    char *type_string;
    int is_deprecated;
    char *default_value;
} FieldInfo;

typedef struct {
    char *name;
    int is_deprecated;
} EnumValueInfo;

typedef struct {
    char *name;
    char *kind;
    char *description;
    FieldInfo *fields;
    int num_fields;
    char **interfaces;
    int num_interfaces;
    EnumValueInfo *enum_values;
    int num_enum_values;
    FieldInfo *input_fields;
    int num_input_fields;
    char **possible_types;
    int num_possible_types;
    char *specified_by_url;
} TypeInfo;

typedef struct {
    char *name;
    ArgInfo *args;
    int num_args;
} DirectiveInfo;

typedef struct {
    TypeInfo *query_type;
    TypeInfo *mutation_type;
    TypeInfo *subscription_type;
    TypeInfo **types;
    int num_types;
    DirectiveInfo *directives;
    int num_directives;
} SchemaData;

/* ------------------------------------------------------------------
 * Function prototypes
 * ------------------------------------------------------------------ */
static void   append_type_string(cJSON *type_obj, char *buffer);
static FieldInfo      *parse_field(cJSON *field_json);
static EnumValueInfo  *parse_enum_value(cJSON *val_json);
static TypeInfo       *parse_type(cJSON *type_json);
static cJSON          *find_type_json_by_name(cJSON *types, const char *target);
static SchemaData     *build_schema_data(cJSON *root);
static void   print_field_info(FILE *out, FieldInfo *field, int indent);
static void   print_type_info(FILE *out, TypeInfo *type, int indent);
static void   print_schema_data(FILE *out, SchemaData *schema);
static void   perform_security_analysis(FILE *out, SchemaData *schema);
static void   free_field_info(FieldInfo *f);
static void   free_type_info(TypeInfo *t);
static void   free_schema_data(SchemaData *schema);
static char  *read_json_from_file(const char *filename, long *out_len);
static char  *capture_introspection_check(const char *filename, size_t *out_len);
int introspection_check(char *intro_json);
int introspection_check_to(FILE *out, char *intro_json);
int detect_graphql(char *api_path, char *graphql_path);
int graphql_scanning(char *path, bool gobuster, char *target_url);

/* ------------------------------------------------------------------
 * append_type_string
 * ------------------------------------------------------------------ */
static void append_type_string(cJSON *type_obj, char *buffer) {
    if (!type_obj) return;

    cJSON *kind = cJSON_GetObjectItem(type_obj, "kind");
    cJSON *name = cJSON_GetObjectItem(type_obj, "name");
    cJSON *of_type = cJSON_GetObjectItem(type_obj, "ofType");

    if (!kind) return;
    const char *kind_str = kind->valuestring;

    if (strcmp(kind_str, "NON_NULL") == 0) {
        append_type_string(of_type, buffer);
        strcat(buffer, "!");
    } else if (strcmp(kind_str, "LIST") == 0) {
        strcat(buffer, "[");
        append_type_string(of_type, buffer);
        strcat(buffer, "]");
    } else {
        if (name && name->valuestring) {
            strcat(buffer, name->valuestring);
        } else {
            strcat(buffer, "Unknown");
        }
    }
}

/* ------------------------------------------------------------------
 * parse_field
 * ------------------------------------------------------------------ */
static FieldInfo* parse_field(cJSON *field_json) {
    FieldInfo *fi = calloc(1, sizeof(FieldInfo));
    if (!fi) return NULL;

    cJSON *name = cJSON_GetObjectItem(field_json, "name");
    if (name && name->valuestring) fi->name = strdup(name->valuestring);

    cJSON *args = cJSON_GetObjectItem(field_json, "args");
    if (args) {
        int count = cJSON_GetArraySize(args);
        fi->num_args = count;
        if (count > 0) {
            fi->args = calloc(count, sizeof(ArgInfo));
            for (int i = 0; i < count; i++) {
                cJSON *arg = cJSON_GetArrayItem(args, i);
                cJSON *arg_name = cJSON_GetObjectItem(arg, "name");
                cJSON *arg_type = cJSON_GetObjectItem(arg, "type");
                if (arg_name && arg_name->valuestring) {
                    fi->args[i].name = strdup(arg_name->valuestring);
                }
                char type_buf[256] = {0};
                append_type_string(arg_type, type_buf);
                fi->args[i].type_string = strdup(type_buf);
            }
        }
    }

    cJSON *type = cJSON_GetObjectItem(field_json, "type");
    if (type) {
        char type_buf[256] = {0};
        append_type_string(type, type_buf);
        fi->type_string = strdup(type_buf);
    }

    cJSON *dep = cJSON_GetObjectItem(field_json, "isDeprecated");
    fi->is_deprecated = (dep && dep->type == cJSON_True);

    cJSON *def = cJSON_GetObjectItem(field_json, "defaultValue");
    if (def && def->valuestring) {
        fi->default_value = strdup(def->valuestring);
    }

    return fi;
}

/* ------------------------------------------------------------------
 * parse_enum_value
 * ------------------------------------------------------------------ */
static EnumValueInfo* parse_enum_value(cJSON *val_json) {
    EnumValueInfo *ev = calloc(1, sizeof(EnumValueInfo));
    if (!ev) return NULL;

    cJSON *name = cJSON_GetObjectItem(val_json, "name");
    if (name && name->valuestring) ev->name = strdup(name->valuestring);

    cJSON *dep = cJSON_GetObjectItem(val_json, "isDeprecated");
    ev->is_deprecated = (dep && dep->type == cJSON_True);

    return ev;
}

/* ------------------------------------------------------------------
 * parse_type
 * ------------------------------------------------------------------ */
static TypeInfo* parse_type(cJSON *type_json) {
    TypeInfo *t = calloc(1, sizeof(TypeInfo));
    if (!t) return NULL;

    cJSON *kind = cJSON_GetObjectItem(type_json, "kind");
    cJSON *name = cJSON_GetObjectItem(type_json, "name");
    cJSON *description = cJSON_GetObjectItem(type_json, "description");

    if (kind && kind->valuestring) t->kind = strdup(kind->valuestring);
    if (name && name->valuestring) t->name = strdup(name->valuestring);
    if (description && description->valuestring) t->description = strdup(description->valuestring);

    const char *kind_str = t->kind;

    if (strcmp(kind_str, "OBJECT") == 0 || strcmp(kind_str, "INTERFACE") == 0) {
        cJSON *fields = cJSON_GetObjectItem(type_json, "fields");
        if (fields) {
            int count = cJSON_GetArraySize(fields);
            t->num_fields = count;
            if (count > 0) {
                t->fields = calloc(count, sizeof(FieldInfo));
                for (int i = 0; i < count; i++) {
                    cJSON *field_json = cJSON_GetArrayItem(fields, i);
                    t->fields[i] = *parse_field(field_json);
                }
            }
        }

        if (strcmp(kind_str, "OBJECT") == 0) {
            cJSON *interfaces = cJSON_GetObjectItem(type_json, "interfaces");
            if (interfaces) {
                int count = cJSON_GetArraySize(interfaces);
                t->num_interfaces = count;
                if (count > 0) {
                    t->interfaces = calloc(count, sizeof(char *));
                    for (int i = 0; i < count; i++) {
                        cJSON *iface = cJSON_GetArrayItem(interfaces, i);
                        cJSON *iface_name = cJSON_GetObjectItem(iface, "name");
                        if (iface_name && iface_name->valuestring) {
                            t->interfaces[i] = strdup(iface_name->valuestring);
                        }
                    }
                }
            }
        }
    }
    else if (strcmp(kind_str, "ENUM") == 0) {
        cJSON *enum_values = cJSON_GetObjectItem(type_json, "enumValues");
        if (enum_values) {
            int count = cJSON_GetArraySize(enum_values);
            t->num_enum_values = count;
            if (count > 0) {
                t->enum_values = calloc(count, sizeof(EnumValueInfo));
                for (int i = 0; i < count; i++) {
                    cJSON *val_json = cJSON_GetArrayItem(enum_values, i);
                    t->enum_values[i] = *parse_enum_value(val_json);
                }
            }
        }
    }
    else if (strcmp(kind_str, "INPUT_OBJECT") == 0) {
        cJSON *input_fields = cJSON_GetObjectItem(type_json, "inputFields");
        if (input_fields) {
            int count = cJSON_GetArraySize(input_fields);
            t->num_input_fields = count;
            if (count > 0) {
                t->input_fields = calloc(count, sizeof(FieldInfo));
                for (int i = 0; i < count; i++) {
                    cJSON *field_json = cJSON_GetArrayItem(input_fields, i);
                    t->input_fields[i] = *parse_field(field_json);
                }
            }
        }
    }
    else if (strcmp(kind_str, "UNION") == 0) {
        cJSON *possible_types = cJSON_GetObjectItem(type_json, "possibleTypes");
        if (possible_types) {
            int count = cJSON_GetArraySize(possible_types);
            t->num_possible_types = count;
            if (count > 0) {
                t->possible_types = calloc(count, sizeof(char *));
                for (int i = 0; i < count; i++) {
                    cJSON *pt = cJSON_GetArrayItem(possible_types, i);
                    cJSON *pt_name = cJSON_GetObjectItem(pt, "name");
                    if (pt_name && pt_name->valuestring) {
                        t->possible_types[i] = strdup(pt_name->valuestring);
                    }
                }
            }
        }
    }
    else if (strcmp(kind_str, "SCALAR") == 0) {
        cJSON *spec_url = cJSON_GetObjectItem(type_json, "specifiedByURL");
        if (spec_url && spec_url->valuestring) {
            t->specified_by_url = strdup(spec_url->valuestring);
        }
    }

    return t;
}

/* ------------------------------------------------------------------
 * find_type_json_by_name
 * ------------------------------------------------------------------ */
static cJSON *find_type_json_by_name(cJSON *types, const char *target) {
    int count = cJSON_GetArraySize(types);
    for (int i = 0; i < count; i++) {
        cJSON *t = cJSON_GetArrayItem(types, i);
        cJSON *tname = cJSON_GetObjectItem(t, "name");
        if (tname && tname->valuestring &&
            strcmp(tname->valuestring, target) == 0) {
            return t;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------
 * build_schema_data
 * ------------------------------------------------------------------ */
static SchemaData* build_schema_data(cJSON *root) {
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        fprintf(stderr, "Error: 'data' key not found.\n");
        return NULL;
    }

    cJSON *schema = cJSON_GetObjectItem(data, "__schema");
    if (!schema) {
        fprintf(stderr, "Error: '__schema' key not found.\n");
        return NULL;
    }

    cJSON *types = cJSON_GetObjectItem(schema, "types");
    if (!types) {
        fprintf(stderr, "Error: 'types' key not found.\n");
        return NULL;
    }

    SchemaData *sdata = calloc(1, sizeof(SchemaData));
    if (!sdata) return NULL;

    cJSON *query_type = cJSON_GetObjectItem(schema, "queryType");
    cJSON *mutation_type = cJSON_GetObjectItem(schema, "mutationType");
    cJSON *subscription_type = cJSON_GetObjectItem(schema, "subscriptionType");

    if (query_type) {
        cJSON *qname = cJSON_GetObjectItem(query_type, "name");
        if (qname && qname->valuestring) {
            cJSON *qobj = find_type_json_by_name(types, qname->valuestring);
            if (qobj) sdata->query_type = parse_type(qobj);
        }
    }

    if (mutation_type) {
        cJSON *mname = cJSON_GetObjectItem(mutation_type, "name");
        if (mname && mname->valuestring) {
            cJSON *mobj = find_type_json_by_name(types, mname->valuestring);
            if (mobj) sdata->mutation_type = parse_type(mobj);
        }
    }

    if (subscription_type) {
        cJSON *sname = cJSON_GetObjectItem(subscription_type, "name");
        if (sname && sname->valuestring) {
            cJSON *sobj = find_type_json_by_name(types, sname->valuestring);
            if (sobj) sdata->subscription_type = parse_type(sobj);
        }
    }

    int total_types = cJSON_GetArraySize(types);
    int custom_count = 0;
    for (int i = 0; i < total_types; i++) {
        cJSON *type = cJSON_GetArrayItem(types, i);
        cJSON *name = cJSON_GetObjectItem(type, "name");
        if (!name || !name->valuestring) continue;
        const char *n = name->valuestring;
        if (strcmp(n, "Boolean") == 0 || strcmp(n, "Int") == 0 ||
            strcmp(n, "String") == 0 || strcmp(n, "Float") == 0 ||
            strcmp(n, "ID") == 0 || strncmp(n, "__", 2) == 0) {
            continue;
        }
        custom_count++;
    }

    sdata->num_types = custom_count;
    if (custom_count > 0) {
        sdata->types = calloc(custom_count, sizeof(TypeInfo *));
        int idx = 0;
        for (int i = 0; i < total_types; i++) {
            cJSON *type = cJSON_GetArrayItem(types, i);
            cJSON *name = cJSON_GetObjectItem(type, "name");
            if (!name || !name->valuestring) continue;
            const char *n = name->valuestring;
            if (strcmp(n, "Boolean") == 0 || strcmp(n, "Int") == 0 ||
                strcmp(n, "String") == 0 || strcmp(n, "Float") == 0 ||
                strcmp(n, "ID") == 0 || strncmp(n, "__", 2) == 0) {
                continue;
            }
            sdata->types[idx++] = parse_type(type);
        }
    }

    cJSON *directives = cJSON_GetObjectItem(schema, "directives");
    if (directives) {
        int dcount = cJSON_GetArraySize(directives);
        sdata->num_directives = dcount;
        if (dcount > 0) {
            sdata->directives = calloc(dcount, sizeof(*sdata->directives));
            for (int i = 0; i < dcount; i++) {
                cJSON *dir = cJSON_GetArrayItem(directives, i);
                cJSON *dname = cJSON_GetObjectItem(dir, "name");
                if (dname && dname->valuestring) {
                    sdata->directives[i].name = strdup(dname->valuestring);
                }
                cJSON *dargs = cJSON_GetObjectItem(dir, "args");
                if (dargs) {
                    int ac = cJSON_GetArraySize(dargs);
                    sdata->directives[i].num_args = ac;
                    if (ac > 0) {
                        sdata->directives[i].args = calloc(ac, sizeof(ArgInfo));
                        for (int j = 0; j < ac; j++) {
                            cJSON *arg = cJSON_GetArrayItem(dargs, j);
                            cJSON *aname = cJSON_GetObjectItem(arg, "name");
                            cJSON *atype = cJSON_GetObjectItem(arg, "type");
                            if (aname && aname->valuestring) {
                                sdata->directives[i].args[j].name = strdup(aname->valuestring);
                            }
                            char buf[256] = {0};
                            append_type_string(atype, buf);
                            sdata->directives[i].args[j].type_string = strdup(buf);
                        }
                    }
                }
            }
        }
    }

    return sdata;
}

/* ------------------------------------------------------------------
 * print_field_info
 * ------------------------------------------------------------------ */
static void print_field_info(FILE *out, FieldInfo *field, int indent) {
    for (int i = 0; i < indent; i++) fprintf(out, "  ");
    fprintf(out, "%s", field->name);

    if (field->num_args > 0) {
        fprintf(out, "(");
        for (int i = 0; i < field->num_args; i++) {
            fprintf(out, "%s: %s", field->args[i].name, field->args[i].type_string);
            if (i < field->num_args - 1) fprintf(out, ", ");
        }
        fprintf(out, ")");
    } else {
        fprintf(out, "()");
    }

    fprintf(out, ": %s", field->type_string);
    if (field->is_deprecated) fprintf(out, " [deprecated]");
    if (field->default_value) fprintf(out, " = %s", field->default_value);
    fprintf(out, "\n");
}

/* ------------------------------------------------------------------
 * print_type_info
 * ------------------------------------------------------------------ */
static void print_type_info(FILE *out, TypeInfo *type, int indent) {
    if (!type) return;

    for (int i = 0; i < indent; i++) fprintf(out, "  ");
    fprintf(out, "%s %s", type->kind, type->name);
    if (type->description) fprintf(out, "  # %s", type->description);
    fprintf(out, "\n");

    const char *kind = type->kind;

    if (strcmp(kind, "OBJECT") == 0 || strcmp(kind, "INTERFACE") == 0) {
        for (int i = 0; i < type->num_fields; i++)
            print_field_info(out, &type->fields[i], indent + 1);

        if (strcmp(kind, "OBJECT") == 0 && type->num_interfaces > 0) {
            for (int i = 0; i < indent + 1; i++) fprintf(out, "  ");
            fprintf(out, "implements ");
            for (int j = 0; j < type->num_interfaces; j++) {
                fprintf(out, "%s", type->interfaces[j]);
                if (j < type->num_interfaces - 1) fprintf(out, ", ");
            }
            fprintf(out, "\n");
        }
        fprintf(out, "\n");
    }
    else if (strcmp(kind, "ENUM") == 0) {
        for (int i = 0; i < type->num_enum_values; i++) {
            for (int j = 0; j < indent + 1; j++) fprintf(out, "  ");
            fprintf(out, "%s", type->enum_values[i].name);
            if (type->enum_values[i].is_deprecated) fprintf(out, " [deprecated]");
            fprintf(out, "\n");
        }
        fprintf(out, "\n");
    }
    else if (strcmp(kind, "INPUT_OBJECT") == 0) {
        for (int i = 0; i < type->num_input_fields; i++)
            print_field_info(out, &type->input_fields[i], indent + 1);
        fprintf(out, "\n");
    }
    else if (strcmp(kind, "SCALAR") == 0) {
        if (type->specified_by_url) {
            for (int i = 0; i < indent + 1; i++) fprintf(out, "  ");
            fprintf(out, "@specifiedBy(url: \"%s\")\n", type->specified_by_url);
        }
        fprintf(out, "\n");
    }
    else if (strcmp(kind, "UNION") == 0) {
        if (type->num_possible_types > 0) {
            for (int i = 0; i < indent + 1; i++) fprintf(out, "  ");
            fprintf(out, "= ");
            for (int j = 0; j < type->num_possible_types; j++) {
                fprintf(out, "%s", type->possible_types[j]);
                if (j < type->num_possible_types - 1) fprintf(out, " | ");
            }
            fprintf(out, "\n\n");
        }
    }
}

/* ------------------------------------------------------------------
 * print_schema_data
 * ------------------------------------------------------------------ */
static void print_schema_data(FILE *out, SchemaData *schema) {
    if (!schema) return;

    fprintf(out, "\n========== GRAPHQL SCHEMA ==========\n\n");

    if (schema->query_type) {
        fprintf(out, "ROOT QUERY:\n");
        print_type_info(out, schema->query_type, 0);
    }
    if (schema->mutation_type) {
        fprintf(out, "ROOT MUTATION:\n");
        print_type_info(out, schema->mutation_type, 0);
    } else {
        fprintf(out, "ROOT MUTATION: (none)\n\n");
    }
    if (schema->subscription_type) {
        fprintf(out, "ROOT SUBSCRIPTION:\n");
        print_type_info(out, schema->subscription_type, 0);
    } else {
        fprintf(out, "ROOT SUBSCRIPTION: (none)\n\n");
    }

    fprintf(out, "ALL CUSTOM TYPES:\n\n");
    for (int i = 0; i < schema->num_types; i++)
        print_type_info(out, schema->types[i], 0);

    if (schema->num_directives > 0) {
        fprintf(out, "DIRECTIVES:\n");
        for (int i = 0; i < schema->num_directives; i++) {
            fprintf(out, "  @%s", schema->directives[i].name);
            if (schema->directives[i].num_args > 0) {
                fprintf(out, "(");
                for (int j = 0; j < schema->directives[i].num_args; j++) {
                    fprintf(out, "%s: %s", schema->directives[i].args[j].name,
                            schema->directives[i].args[j].type_string);
                    if (j < schema->directives[i].num_args - 1) fprintf(out, ", ");
                }
                fprintf(out, ")");
            }
            fprintf(out, "\n");
        }
        fprintf(out, "\n");
    }

    fprintf(out, "SUMMARY: %d custom types, %d directives\n\n",
            schema->num_types, schema->num_directives);
}

/* ------------------------------------------------------------------
 * perform_security_analysis
 * ------------------------------------------------------------------ */
static void perform_security_analysis(FILE *out, SchemaData *schema) {
    if (!schema) return;

    fprintf(out, "========== SECURITY ANALYSIS ==========\n\n");

    const char *sensitive_keywords[] = {
        "password", "pass", "secret", "token", "apiKey", "apikey",
        "credit", "card", "ssn", "social", "tax", "bank", "account",
        "private", "internal", "admin", "root", "superuser"
    };
    int num_keywords = sizeof(sensitive_keywords) / sizeof(sensitive_keywords[0]);

    fprintf(out, "SENSITIVE FIELDS:\n");
    int found_sensitive = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                for (int k = 0; k < num_keywords; k++) {
                    if (strstr(f->name, sensitive_keywords[k]) != NULL) {
                        fprintf(out, "  %s.%s : %s\n", t->name, f->name, f->type_string);
                        found_sensitive++;
                        break;
                    }
                }
            }
        }
        if (strcmp(t->kind, "INPUT_OBJECT") == 0) {
            for (int j = 0; j < t->num_input_fields; j++) {
                FieldInfo *f = &t->input_fields[j];
                for (int k = 0; k < num_keywords; k++) {
                    if (strstr(f->name, sensitive_keywords[k]) != NULL) {
                        fprintf(out, "  %s (input) : %s\n", f->name, f->type_string);
                        found_sensitive++;
                        break;
                    }
                }
            }
        }
    }
    if (!found_sensitive) fprintf(out, "  (none)\n");

    if (schema->mutation_type) {
        fprintf(out, "\nMUTATIONS (data modification):\n");
        TypeInfo *mut = schema->mutation_type;
        for (int i = 0; i < mut->num_fields; i++) {
            FieldInfo *f = &mut->fields[i];
            fprintf(out, "  %s(", f->name);
            for (int j = 0; j < f->num_args; j++) {
                fprintf(out, "%s: %s", f->args[j].name, f->args[j].type_string);
                if (j < f->num_args - 1) fprintf(out, ", ");
            }
            fprintf(out, ") -> %s\n", f->type_string);
        }
    } else {
        fprintf(out, "\nMUTATIONS: (none)\n");
    }

    fprintf(out, "\nLIST FIELDS (possible DoS):\n");
    int found_lists = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                if (strstr(f->type_string, "[") != NULL) {
                    fprintf(out, "  %s.%s : %s\n", t->name, f->name, f->type_string);
                    found_lists++;
                }
            }
        }
    }
    if (!found_lists) fprintf(out, "  (none)\n");

    const char *scalars[] = {"String", "Int", "Float", "Boolean", "ID"};
    int num_scalars = 5;
    fprintf(out, "\nOBJECT FIELDS (deep nesting potential):\n");
    int found_objects = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                int is_scalar = 0;
                for (int k = 0; k < num_scalars; k++) {
                    if (strcmp(f->type_string, scalars[k]) == 0) {
                        is_scalar = 1;
                        break;
                    }
                }
                if (!is_scalar && strchr(f->type_string, '[') == NULL) {
                    fprintf(out, "  %s.%s -> %s\n", t->name, f->name, f->type_string);
                    found_objects++;
                }
            }
        }
    }
    if (!found_objects) fprintf(out, "  (none)\n");

    fprintf(out, "\nDEPRECATED FIELDS:\n");
    int found_deprecated = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                if (t->fields[j].is_deprecated) {
                    fprintf(out, "  %s.%s\n", t->name, t->fields[j].name);
                    found_deprecated++;
                }
            }
        }
        if (strcmp(t->kind, "ENUM") == 0) {
            for (int j = 0; j < t->num_enum_values; j++) {
                if (t->enum_values[j].is_deprecated) {
                    fprintf(out, "  %s.%s (enum)\n", t->name, t->enum_values[j].name);
                    found_deprecated++;
                }
            }
        }
    }
    if (!found_deprecated) fprintf(out, "  (none)\n");

    fprintf(out, "\nRECOMMENDATIONS:\n");
    if (schema->mutation_type) fprintf(out, "  - Mutations exist: enforce authentication and authorization.\n");
    if (found_sensitive) fprintf(out, "  - Sensitive fields exposed: restrict access or use field-level permissions.\n");
    if (found_lists) fprintf(out, "  - List fields: implement pagination (first, after) to prevent DoS.\n");
    if (found_objects) fprintf(out, "  - Object fields: implement query depth limiting.\n");
    fprintf(out, "  - Disable introspection in production unless required.\n");
    fprintf(out, "=========================================\n\n");
}

/* ------------------------------------------------------------------
 * free_field_info / free_type_info
 * ------------------------------------------------------------------ */
static void free_field_info(FieldInfo *f) {
    if (!f) return;
    free(f->name);
    free(f->type_string);
    free(f->default_value);
    for (int i = 0; i < f->num_args; i++) {
        free(f->args[i].name);
        free(f->args[i].type_string);
    }
    free(f->args);
}

static void free_type_info(TypeInfo *t) {
    if (!t) return;
    free(t->name);
    free(t->kind);
    free(t->description);

    for (int i = 0; i < t->num_fields; i++) free_field_info(&t->fields[i]);
    free(t->fields);

    for (int i = 0; i < t->num_interfaces; i++) free(t->interfaces[i]);
    free(t->interfaces);

    for (int i = 0; i < t->num_enum_values; i++) free(t->enum_values[i].name);
    free(t->enum_values);

    for (int i = 0; i < t->num_input_fields; i++) free_field_info(&t->input_fields[i]);
    free(t->input_fields);

    for (int i = 0; i < t->num_possible_types; i++) free(t->possible_types[i]);
    free(t->possible_types);

    free(t->specified_by_url);
    free(t);
}

static void free_schema_data(SchemaData *schema) {
    if (!schema) return;

    if (schema->query_type)        free_type_info(schema->query_type);
    if (schema->mutation_type)     free_type_info(schema->mutation_type);
    if (schema->subscription_type) free_type_info(schema->subscription_type);

    for (int i = 0; i < schema->num_types; i++) {
        if (schema->types[i]) free_type_info(schema->types[i]);
    }
    free(schema->types);

    for (int i = 0; i < schema->num_directives; i++) {
        free(schema->directives[i].name);
        for (int j = 0; j < schema->directives[i].num_args; j++) {
            free(schema->directives[i].args[j].name);
            free(schema->directives[i].args[j].type_string);
        }
        free(schema->directives[i].args);
    }
    free(schema->directives);

    free(schema);
}

/* ------------------------------------------------------------------
 * read_json_from_file
 * ------------------------------------------------------------------ */
static char* read_json_from_file(const char *filename, long *out_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = malloc(length + 1);
    if (!data) { fclose(file); return NULL; }

    size_t read_len = fread(data, 1, length, file);
    fclose(file);
    if (read_len != (size_t)length) {
        free(data);
        return NULL;
    }
    data[length] = '\0';

    char *start = strchr(data, '{');
    if (!start) {
        free(data);
        return NULL;
    }

    if (start != data) {
        memmove(data, start, length - (start - data));
        length = length - (start - data);
        data[length] = '\0';
    }

    if (out_len) *out_len = length;
    return data;
}

/* ------------------------------------------------------------------
 * capture_introspection_check — writes analysis to a temp file and
 * reads it back into a heap string.
 * ------------------------------------------------------------------ */
static char* capture_introspection_check(const char *filename, size_t *out_len) {
    char tmpl[] = "/tmp/sentinel_analysis_XXXXXX";
    int tmpfd = mkstemp(tmpl);
    if (tmpfd < 0) return NULL;

    FILE *tmp = fdopen(tmpfd, "w+");
    if (!tmp) {
        close(tmpfd);
        unlink(tmpl);
        return NULL;
    }

    int rc = introspection_check_to(tmp, (char *)filename);
    fflush(tmp);

    if (fseek(tmp, 0, SEEK_END) != 0) { fclose(tmp); unlink(tmpl); return NULL; }
    long len = ftell(tmp);
    if (len < 0 || rc != 0) {
        fclose(tmp);
        unlink(tmpl);
        return NULL;
    }
    rewind(tmp);

    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(tmp); unlink(tmpl); return NULL; }

    size_t got = fread(buf, 1, (size_t)len, tmp);
    buf[got] = '\0';

    fclose(tmp);
    unlink(tmpl);

    if (got == 0) { free(buf); return NULL; }
    if (out_len) *out_len = got;
    return buf;
}

/* ------------------------------------------------------------------
 * introspection_check_to / introspection_check
 * ------------------------------------------------------------------ */
int introspection_check_to(FILE *out, char *intro_json) {
    long length;
    char *data = read_json_from_file(intro_json, &length);
    if (!data) {
        fprintf(stderr, "Failed to read JSON from %s\n", intro_json);
        return 1;
    }

    cJSON *json = cJSON_Parse(data);
    free(data);

    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) fprintf(stderr, "JSON Parse Error: %s\n", error_ptr);
        return 1;
    }

    SchemaData *schema = build_schema_data(json);
    if (!schema) {
        cJSON_Delete(json);
        return 1;
    }

    print_schema_data(out, schema);
    perform_security_analysis(out, schema);
    free_schema_data(schema);
    cJSON_Delete(json);
    return 0;
}

int introspection_check(char *intro_json) {
    return introspection_check_to(stdout, intro_json);
}



// SCANNER FUNCTIONS TO LEARN PEDRO









/* ------------------------------------------------------------------
 * detect_graphql
 * ------------------------------------------------------------------ */
int detect_graphql(char *api_path, char *graphql_path) {
    request r = {0};

    FILE *f = fopen("glassworm/graphql/uni.json", "r");
    if (!f) {
        fprintf(stderr, "Failed to open uni.json\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long json_size = ftell(f);
    rewind(f);

    char *json = malloc(json_size + 1);
    if (!json) { fclose(f); return 1; }
    if ((long)fread(json, 1, json_size, f) != json_size) {
        free(json); fclose(f); return 1;
    }
    json[json_size] = '\0';
    fclose(f);

    FILE *api = fopen(api_path, "r");
    if (!api) { free(json); return 1; }

    FILE *graphql = fopen(graphql_path, "w");
    if (!graphql) { free(json); fclose(api); return 1; }

    char api_url[256];
    int found_any = 0;

    while (fgets(api_url, sizeof(api_url), api)) {
        api_url[strcspn(api_url, "\n")] = '\0';

        if (!http_send_post(&r, api_url, false, NULL, true, json)) {
            fprintf(stderr, "HTTP POST failed for %s\n", api_url);
            continue;
        }

        if (r.code != 200) {
            fprintf(stderr, "Non-200 response for %s\n", api_url);
            continue;
        }

        char *resp = read_json_from_file(r.filename, NULL);
        if (!resp) continue;

        if (strstr(resp, "__schema") || strstr(resp, "\"data\"") ||
            strstr(resp, "\"errors\"") || strstr(resp, "\"query\"")) {
            printf("[+] GraphQL detected at %s\n", api_url);
            fprintf(graphql, "%s\n", api_url);
            found_any = 1;
        }
        free(resp);
    }

    fclose(api);
    fclose(graphql);
    free(json);
    return found_any ? 0 : 1;
}

/* ------------------------------------------------------------------
 * graphql_scanning
 * ------------------------------------------------------------------ */
int graphql_scanning(char *path, bool gobuster, char *target_url) {
    FILE *graphql_file = NULL;

    FILE *f = fopen("glassworm/graphql/introspection.json", "r");
    if (!f) {
        fprintf(stderr, "Failed to open introspection.json\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long json_size = ftell(f);
    rewind(f);

    char *introspection_json = malloc(json_size + 1);
    if (!introspection_json ||
        (long)fread(introspection_json, 1, json_size, f) != json_size) {
        free(introspection_json);
        fclose(f);
        return 1;
    }
    introspection_json[json_size] = '\0';
    fclose(f);

    char api_path[512];
    char graphql_path[512];

    snprintf(api_path,      sizeof(api_path),      "%s/api.txt",      path);
    snprintf(graphql_path,  sizeof(graphql_path),  "%s/graphql.txt",  path);

    if (gobuster) {
        char gobuster_path[512];
        snprintf(gobuster_path, sizeof(gobuster_path), "%s/gobuster.txt", path);

        FILE *gobuster_file = fopen(gobuster_path, "r");
        if (!gobuster_file) {
            fprintf(stderr, "Failed to open gobuster.txt\n");
            free(introspection_json);
            return 1;
        }
        FILE *api_file = fopen(api_path, "w");
        if (!api_file) {
            fclose(gobuster_file);
            free(introspection_json);
            return 1;
        }
        char gobuster_url[512];
        while (fgets(gobuster_url, sizeof(gobuster_url), gobuster_file)) {
            gobuster_url[strcspn(gobuster_url, "\n")] = '\0';
            if (strstr(gobuster_url, "graphql") || strstr(gobuster_url, "api")) {
                fprintf(api_file, "%s\n", gobuster_url);
            }
        }
        fclose(gobuster_file);
        fclose(api_file);

        if (detect_graphql(api_path, graphql_path) == 0)
            printf("[+] GraphQL detection completed.\n");
        else
            printf("[-] No GraphQL endpoints found.\n");

        graphql_file = fopen(graphql_path, "r");
        if (!graphql_file) {
            fprintf(stderr, "Failed to open graphql.txt\n");
            free(introspection_json);
            return 1;
        }

    } else {

        FILE *api_file = fopen(api_path, "w");
        if (!api_file) {
            free(introspection_json);
            return 1;
        }
        fprintf(api_file, "%s\n", target_url);
        fclose(api_file);

        if (detect_graphql(api_path, graphql_path) == 0)
            printf("[+] GraphQL detection completed.\n");
        else
            printf("[-] No GraphQL endpoints found.\n");

        graphql_file = fopen(graphql_path, "r");
        if (!graphql_file) {
            fprintf(stderr, "Failed to open graphql.txt\n");
            free(introspection_json);
            return 1;
        }
    }

    /* ---------------- main loop ---------------- */
    request r = {0};
    char graphql_url[1028];
    int  sent_count = 0;

    while (fgets(graphql_url, sizeof(graphql_url), graphql_file)) {
        graphql_url[strcspn(graphql_url, "\n")] = '\0';
        if (graphql_url[0] == '\0') continue;

        /* 1) POST the introspection query to this endpoint. */
        if (!http_send_post(&r, graphql_url, false, NULL, true, introspection_json)) {
            fprintf(stderr, "[-] HTTP POST failed for %s\n", graphql_url);
            continue;
        }
        if (r.code != 200) {
            fprintf(stderr, "[-] Non-200 (%d) from %s\n", (int)r.code, graphql_url);
            continue;
        }
        sent_count++;
        printf("[+] Response from %s saved to %s\n", graphql_url, r.filename);

        /* 2) Analyze the saved JSON response, capturing stdout as a string. */
        size_t analysis_len = 0;
        char  *analysis = capture_introspection_check(r.filename, &analysis_len);
        if (!analysis) {
            fprintf(stderr, "[-] analysis failed for %s\n", graphql_url);
            continue;
        }

        /* Read the raw response file back in for inclusion in the message. */
        FILE *file = fopen(r.filename, "rb");
        if (!file) {
            fprintf(stderr, "[-] cannot open %s\n", r.filename);
            free(analysis);
            continue;
        }
        if (fseek(file, 0, SEEK_END) != 0) {
            fprintf(stderr, "[-] fseek failed for %s\n", r.filename);
            fclose(file);
            free(analysis);
            continue;
        }
        long file_size = ftell(file);
        if (file_size < 0) {
            fprintf(stderr, "[-] ftell failed for %s\n", r.filename);
            fclose(file);
            free(analysis);
            continue;
        }
        rewind(file);

        char *file_contents = malloc((size_t)file_size + 1);
        if (!file_contents) {
            fprintf(stderr, "[-] malloc failed for %s\n", graphql_url);
            fclose(file);
            free(analysis);
            continue;
        }
        size_t bytes_read = fread(file_contents, 1, (size_t)file_size, file);
        file_contents[bytes_read] = '\0';
        fclose(file);

        /* Build the combined message. */
        size_t raw_len = strlen(file_contents);
        size_t msg_len = analysis_len + raw_len + 64;
        char  *msg     = malloc(msg_len);
        if (!msg) {
            fprintf(stderr, "[-] malloc failed for %s\n", graphql_url);
            free(file_contents);
            free(analysis);
            continue;
        }
        int written = snprintf(msg, msg_len,
                               "Analysis Results:\n %s \nInspection Raw:\n %s \n",
                               analysis, file_contents);
        free(file_contents);

        if (written < 0 || (size_t)written >= msg_len) {
            fprintf(stderr, "[-] snprintf truncation for %s\n", graphql_url);
            free(msg);
            free(analysis);
            continue;
        }
        printf("%s \n", msg);
        /* 3) Stand up the socket and hand the message to whoever connects. */
        int fd = init_socket(SOCK_PATH);
        if (fd < 0) {
            fprintf(stderr, "[-] init_socket failed for %s\n", graphql_url);
            free(msg);
            free(analysis);
            continue;
        }
        int client = accept_connection(fd);
        if (client < 0) {
            fprintf(stderr, "[-] accept_connection failed for %s\n", graphql_url);
            free(msg);
            free(analysis);
            close_socket(fd, client, SOCK_PATH);
            continue;
        }

        if (send_message(client, msg) < 0) {
            fprintf(stderr, "[-] socket send (analysis) failed for %s\n",
                    graphql_url);
            free(msg);
            free(analysis);
            close_socket(fd, client, SOCK_PATH);
            continue;
        }
        printf("[+] Sent analysis (%d bytes) for %s\n", written, graphql_url);

        free(msg);
        free(analysis);
        close_socket(fd, client, SOCK_PATH);
    }

    fclose(graphql_file);
    free(introspection_json);
    printf("\n[+] Done. %d introspection responses analyzed.\n", sent_count);

    return 0;
}