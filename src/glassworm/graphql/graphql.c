#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#include "../http/http.h"
#include "../sock/sock.h"
#define SOCK_PATH "/tmp/myapp.sock"
// ------------------------------------------------------------------
// Data structures
// ------------------------------------------------------------------

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
    TypeInfo *query_type;
    TypeInfo *mutation_type;
    TypeInfo *subscription_type;
    TypeInfo **types;
    int num_types;
    struct {
        char *name;
        ArgInfo *args;
        int num_args;
    } *directives;
    int num_directives;
} SchemaData;

// ------------------------------------------------------------------
// Function prototypes
// ------------------------------------------------------------------
static void append_type_string(cJSON *type_obj, char *buffer);
static FieldInfo* parse_field(cJSON *field_json);
static EnumValueInfo* parse_enum_value(cJSON *val_json);
static TypeInfo* parse_type(cJSON *type_json);
static SchemaData* build_schema_data(cJSON *root);
static void print_schema_data(SchemaData *schema);
static void free_schema_data(SchemaData *schema);
static void perform_security_analysis(SchemaData *schema);
static char* read_json_from_file(const char *filename, long *out_len);

// ------------------------------------------------------------------
// Helper: unwrap a GraphQL type (LIST, NON_NULL) into a string
// ------------------------------------------------------------------
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

// ------------------------------------------------------------------
// Parse a single field
// ------------------------------------------------------------------
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

// ------------------------------------------------------------------
// Parse an enum value
// ------------------------------------------------------------------
static EnumValueInfo* parse_enum_value(cJSON *val_json) {
    EnumValueInfo *ev = calloc(1, sizeof(EnumValueInfo));
    if (!ev) return NULL;

    cJSON *name = cJSON_GetObjectItem(val_json, "name");
    if (name && name->valuestring) ev->name = strdup(name->valuestring);

    cJSON *dep = cJSON_GetObjectItem(val_json, "isDeprecated");
    ev->is_deprecated = (dep && dep->type == cJSON_True);

    return ev;
}

// ------------------------------------------------------------------
// Parse a type
// ------------------------------------------------------------------
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

// ------------------------------------------------------------------
// Build schema data from JSON
// ------------------------------------------------------------------
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

    cJSON *find_type_json_by_name(cJSON * types, const char * target) {
        int count = cJSON_GetArraySize(types);
        for (int i = 0; i < count; i++) {
            cJSON *t = cJSON_GetArrayItem(types, i);
            cJSON *tname = cJSON_GetObjectItem(t, "name");
            if (tname && tname->valuestring && strcmp(tname->valuestring, target) == 0) {
                return t;
            }
        }
        return NULL;
    }

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

// ------------------------------------------------------------------
// Print a field (compact)
// ------------------------------------------------------------------
static void print_field_info(FieldInfo *field, int indent) {
    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s", field->name);

    if (field->num_args > 0) {
        printf("(");
        for (int i = 0; i < field->num_args; i++) {
            printf("%s: %s", field->args[i].name, field->args[i].type_string);
            if (i < field->num_args - 1) printf(", ");
        }
        printf(")");
    } else {
        printf("()");
    }

    printf(": %s", field->type_string);
    if (field->is_deprecated) printf(" [deprecated]");
    if (field->default_value) printf(" = %s", field->default_value);
    printf("\n");
}

// ------------------------------------------------------------------
// Print a type (compact)
// ------------------------------------------------------------------
static void print_type_info(TypeInfo *type, int indent) {
    if (!type) return;

    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s %s", type->kind, type->name);
    if (type->description) {
        printf("  # %s", type->description);
    }
    printf("\n");

    const char *kind = type->kind;

    if (strcmp(kind, "OBJECT") == 0 || strcmp(kind, "INTERFACE") == 0) {
        for (int i = 0; i < type->num_fields; i++) {
            print_field_info(&type->fields[i], indent + 1);
        }
        if (strcmp(kind, "OBJECT") == 0 && type->num_interfaces > 0) {
            for (int i = 0; i < indent + 1; i++) printf("  ");
            printf("implements ");
            for (int j = 0; j < type->num_interfaces; j++) {
                printf("%s", type->interfaces[j]);
                if (j < type->num_interfaces - 1) printf(", ");
            }
            printf("\n");
        }
        printf("\n");
    }
    else if (strcmp(kind, "ENUM") == 0) {
        for (int i = 0; i < type->num_enum_values; i++) {
            for (int j = 0; j < indent + 1; j++) printf("  ");
            printf("%s", type->enum_values[i].name);
            if (type->enum_values[i].is_deprecated) printf(" [deprecated]");
            printf("\n");
        }
        printf("\n");
    }
    else if (strcmp(kind, "INPUT_OBJECT") == 0) {
        for (int i = 0; i < type->num_input_fields; i++) {
            print_field_info(&type->input_fields[i], indent + 1);
        }
        printf("\n");
    }
    else if (strcmp(kind, "SCALAR") == 0) {
        if (type->specified_by_url) {
            for (int i = 0; i < indent + 1; i++) printf("  ");
            printf("@specifiedBy(url: \"%s\")\n", type->specified_by_url);
        }
        printf("\n");
    }
    else if (strcmp(kind, "UNION") == 0) {
        if (type->num_possible_types > 0) {
            for (int i = 0; i < indent + 1; i++) printf("  ");
            printf("= ");
            for (int j = 0; j < type->num_possible_types; j++) {
                printf("%s", type->possible_types[j]);
                if (j < type->num_possible_types - 1) printf(" | ");
            }
            printf("\n\n");
        }
    }
}

// ------------------------------------------------------------------
// Print the entire schema (compact)
// ------------------------------------------------------------------
static void print_schema_data(SchemaData *schema) {
    if (!schema) return;

    printf("\n========== GRAPHQL SCHEMA ==========\n\n");

    if (schema->query_type) {
        printf("ROOT QUERY:\n");
        print_type_info(schema->query_type, 0);
    }
    if (schema->mutation_type) {
        printf("ROOT MUTATION:\n");
        print_type_info(schema->mutation_type, 0);
    } else {
        printf("ROOT MUTATION: (none)\n\n");
    }
    if (schema->subscription_type) {
        printf("ROOT SUBSCRIPTION:\n");
        print_type_info(schema->subscription_type, 0);
    } else {
        printf("ROOT SUBSCRIPTION: (none)\n\n");
    }

    printf("ALL CUSTOM TYPES:\n\n");
    for (int i = 0; i < schema->num_types; i++) {
        print_type_info(schema->types[i], 0);
    }

    if (schema->num_directives > 0) {
        printf("DIRECTIVES:\n");
        for (int i = 0; i < schema->num_directives; i++) {
            printf("  @%s", schema->directives[i].name);
            if (schema->directives[i].num_args > 0) {
                printf("(");
                for (int j = 0; j < schema->directives[i].num_args; j++) {
                    printf("%s: %s", schema->directives[i].args[j].name,
                           schema->directives[i].args[j].type_string);
                    if (j < schema->directives[i].num_args - 1) printf(", ");
                }
                printf(")");
            }
            printf("\n");
        }
        printf("\n");
    }

    printf("SUMMARY: %d custom types, %d directives\n\n",
           schema->num_types, schema->num_directives);
}

// ------------------------------------------------------------------
// Security analysis (no emojis, concise)
// ------------------------------------------------------------------
static void perform_security_analysis(SchemaData *schema) {
    if (!schema) return;

    printf("========== SECURITY ANALYSIS ==========\n\n");

    // 1. Sensitive fields
    const char *sensitive_keywords[] = {
        "password", "pass", "secret", "token", "apiKey", "apikey",
        "credit", "card", "ssn", "social", "tax", "bank", "account",
        "private", "internal", "admin", "root", "superuser"
    };
    int num_keywords = sizeof(sensitive_keywords) / sizeof(sensitive_keywords[0]);

    printf("SENSITIVE FIELDS:\n");
    int found_sensitive = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                for (int k = 0; k < num_keywords; k++) {
                    if (strstr(f->name, sensitive_keywords[k]) != NULL) {
                        printf("  %s.%s : %s\n", t->name, f->name, f->type_string);
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
                        printf("  %s (input) : %s\n", f->name, f->type_string);
                        found_sensitive++;
                        break;
                    }
                }
            }
        }
    }
    if (!found_sensitive) printf("  (none)\n");

    // 2. Mutations
    if (schema->mutation_type) {
        printf("\nMUTATIONS (data modification):\n");
        TypeInfo *mut = schema->mutation_type;
        for (int i = 0; i < mut->num_fields; i++) {
            FieldInfo *f = &mut->fields[i];
            printf("  %s(", f->name);
            for (int j = 0; j < f->num_args; j++) {
                printf("%s: %s", f->args[j].name, f->args[j].type_string);
                if (j < f->num_args - 1) printf(", ");
            }
            printf(") -> %s\n", f->type_string);
        }
    } else {
        printf("\nMUTATIONS: (none)\n");
    }

    // 3. List fields (DoS risk)
    printf("\nLIST FIELDS (possible DoS):\n");
    int found_lists = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                if (strstr(f->type_string, "[") != NULL) {
                    printf("  %s.%s : %s\n", t->name, f->name, f->type_string);
                    found_lists++;
                }
            }
        }
    }
    if (!found_lists) printf("  (none)\n");

    // 4. Object fields (nesting risk)
    const char *scalars[] = {"String", "Int", "Float", "Boolean", "ID"};
    int num_scalars = 5;
    printf("\nOBJECT FIELDS (deep nesting potential):\n");
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
                    printf("  %s.%s -> %s\n", t->name, f->name, f->type_string);
                    found_objects++;
                }
            }
        }
    }
    if (!found_objects) printf("  (none)\n");

    // 5. Deprecated fields
    printf("\nDEPRECATED FIELDS:\n");
    int found_deprecated = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                if (t->fields[j].is_deprecated) {
                    printf("  %s.%s\n", t->name, t->fields[j].name);
                    found_deprecated++;
                }
            }
        }
        if (strcmp(t->kind, "ENUM") == 0) {
            for (int j = 0; j < t->num_enum_values; j++) {
                if (t->enum_values[j].is_deprecated) {
                    printf("  %s.%s (enum)\n", t->name, t->enum_values[j].name);
                    found_deprecated++;
                }
            }
        }
    }
    if (!found_deprecated) printf("  (none)\n");

    // 6. Recommendations
    printf("\nRECOMMENDATIONS:\n");
    if (schema->mutation_type) printf("  - Mutations exist: enforce authentication and authorization.\n");
    if (found_sensitive) printf("  - Sensitive fields exposed: restrict access or use field-level permissions.\n");
    if (found_lists) printf("  - List fields: implement pagination (first, after) to prevent DoS.\n");
    if (found_objects) printf("  - Object fields: implement query depth limiting.\n");
    printf("  - Disable introspection in production unless required.\n");
    printf("=========================================\n\n");
}


// ------------------------------------------------------------------
// Free SchemaData
// ------------------------------------------------------------------
static void free_schema_data(SchemaData *schema) {
    if (!schema) return;

    // Helper to free a FieldInfo
    void free_field_info(FieldInfo *f) {
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

    // Helper to free a TypeInfo
    void free_type_info(TypeInfo *t) {
        if (!t) return;
        free(t->name);
        free(t->kind);
        free(t->description);
        
        // Free fields
        for (int i = 0; i < t->num_fields; i++) {
            free_field_info(&t->fields[i]);
        }
        free(t->fields);
        
        // Free interfaces
        for (int i = 0; i < t->num_interfaces; i++) {
            free(t->interfaces[i]);
        }
        free(t->interfaces);
        
        // Free enum values
        for (int i = 0; i < t->num_enum_values; i++) {
            free(t->enum_values[i].name);
        }
        free(t->enum_values);
        
        // Free input fields
        for (int i = 0; i < t->num_input_fields; i++) {
            free_field_info(&t->input_fields[i]);
        }
        free(t->input_fields);
        
        // Free possible types
        for (int i = 0; i < t->num_possible_types; i++) {
            free(t->possible_types[i]);
        }
        free(t->possible_types);
        
        free(t->specified_by_url);
        free(t);
    }

    // Free query_type
    if (schema->query_type) {
        free_type_info(schema->query_type);
    }

    // Free mutation_type
    if (schema->mutation_type) {
        free_type_info(schema->mutation_type);
    }

    // Free subscription_type
    if (schema->subscription_type) {
        free_type_info(schema->subscription_type);
    }

    // Free all types
    for (int i = 0; i < schema->num_types; i++) {
        if (schema->types[i]) {
            free_type_info(schema->types[i]);
        }
    }
    free(schema->types);

    // Free directives
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

// ------------------------------------------------------------------
// Helper: read file and skip non-JSON preamble
// ------------------------------------------------------------------
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
        memmove(data, start, length - (start - data) + 1);
        length = length - (start - data);
    }

    if (out_len) *out_len = length;
    return data;
}

// ------------------------------------------------------------------
// Main analysis entry point
// ------------------------------------------------------------------
int introspection_check(char *intro_json) {
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
    if (schema) {
        print_schema_data(schema);
        perform_security_analysis(schema);
        free_schema_data(schema);
        cJSON_Delete(json);
        return 0;
    }

    cJSON_Delete(json);
    return 1;
}

// ------------------------------------------------------------------
// Detect GraphQL endpoints with a lightweight probe
// ------------------------------------------------------------------
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

// ------------------------------------------------------------------
// Main orchestration function
// ------------------------------------------------------------------
int graphql_scanning(char *path) {
    // socket communication
    int fd = init_socket(SOCK_PATH);
    int client = accept_connection(fd);
    char input_buffer[4096];



    char gobuster_path[512];
    snprintf(gobuster_path, sizeof(gobuster_path), "%s/gobuster.txt", path);

    char api_path[512];
    snprintf(api_path, sizeof(api_path), "%s/api.txt", path);

    char graphql_path[512];
    snprintf(graphql_path, sizeof(graphql_path), "%s/graphql.txt", path);

    // Filter gobuster.txt -> api.txt
    FILE *gobuster_file = fopen(gobuster_path, "r");
    if (!gobuster_file) {
        fprintf(stderr, "Failed to open gobuster.txt\n");
        return 1;
    }

    FILE *api_file = fopen(api_path, "w");
    if (!api_file) {
        fclose(gobuster_file);
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

    // Detect GraphQL endpoints
    int detect_ret = detect_graphql(api_path, graphql_path);
    if (detect_ret == 0)
        printf("[+] GraphQL detection completed.\n");
    else
        printf("[-] No GraphQL endpoints found.\n");

    // Read full introspection query
    FILE *graphql_file = fopen(graphql_path, "r");
    if (!graphql_file) {
        fprintf(stderr, "Failed to open graphql.txt\n");
        return 1;
    }

    FILE *f = fopen("glassworm/graphql/introspection.json", "r");
    if (!f) {
        fprintf(stderr, "Failed to open introspection.json\n");
        fclose(graphql_file);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long json_size = ftell(f);
    rewind(f);

    char *json = malloc(json_size + 1);
    if (!json) { fclose(f); fclose(graphql_file); return 1; }
    if ((long)fread(json, 1, json_size, f) != json_size) {
        free(json); fclose(f); fclose(graphql_file); return 1;
    }
    json[json_size] = '\0';
    fclose(f);

    request r = {0};
    char graphql_url[1028];
    int sent_count = 0;

    while (fgets(graphql_url, sizeof(graphql_url), graphql_file)) {
        graphql_url[strcspn(graphql_url, "\n")] = '\0';

        if (http_send_post(&r, graphql_url, false, NULL, true, json)) {
            printf("[+] Sent introspection to %s, response saved to %s\n",
                   graphql_url, r.filename);

            sent_count++;

            // Analyze the response immediately
            printf("\n--- Analysis for %s ---\n", graphql_url);
            introspection_check(r.filename);
            send_message(client, introspection_check(r.filename));
            
            receive_message(client, input_buffer, sizeof(input_buffer));

            if (!http_send_post(&r, api_url, false, NULL, true, input_buffer)) {
                fprintf(stderr, "HTTP POST failed for %s\n", api_url);
            }

            continue;
        }

            printf("------------------------\n");
        } else {
            fprintf(stderr, "[-] Failed to send introspection to %s\n", graphql_url);
        }
    }

    fclose(graphql_file);
    free(json);
    printf("\n[+] Done. %d introspection responses analyzed.\n", sent_count);
    close_socket(fd, client);
    return 0;
}