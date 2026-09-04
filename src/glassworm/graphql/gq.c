#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// ------------------------------------------------------------------
// Data structures
// ------------------------------------------------------------------

// Argument of a field
typedef struct {
    char *name;          // argument name
    char *type_string;   // e.g., "String!", "[Int]"
} ArgInfo;

// A field (for OBJECT, INTERFACE, INPUT_OBJECT)
typedef struct {
    char *name;
    ArgInfo *args;       // dynamic array
    int num_args;
    char *type_string;   // return type (or input type)
    int is_deprecated;
    // For input object fields, there may be a default value:
    char *default_value; // NULL if none
} FieldInfo;

// Enum value
typedef struct {
    char *name;
    int is_deprecated;
} EnumValueInfo;

// A type definition
typedef struct {
    char *name;
    char *kind;          // "OBJECT", "INTERFACE", "ENUM", "UNION", "SCALAR", "INPUT_OBJECT"
    char *description;   // optional, may be NULL
    // For OBJECT and INTERFACE:
    FieldInfo *fields;
    int num_fields;
    // For OBJECT only: list of interface names it implements
    char **interfaces;
    int num_interfaces;
    // For ENUM:
    EnumValueInfo *enum_values;
    int num_enum_values;
    // For INPUT_OBJECT:
    FieldInfo *input_fields; // same structure as fields
    int num_input_fields;
    // For UNION:
    char **possible_types; // names
    int num_possible_types;
    // For SCALAR:
    char *specified_by_url;
} TypeInfo;

// The complete schema
typedef struct {
    TypeInfo *query_type;        // root Query object
    TypeInfo *mutation_type;     // root Mutation (may be NULL)
    TypeInfo *subscription_type; // root Subscription (may be NULL)
    TypeInfo **types;            // all custom types (excluding built‑ins and internal)
    int num_types;
    // Directives
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
        // SCALAR, OBJECT, ENUM, INTERFACE, UNION, INPUT_OBJECT
        if (name && name->valuestring) {
            strcat(buffer, name->valuestring);
        } else {
            strcat(buffer, "Unknown");
        }
    }
}

// ------------------------------------------------------------------
// Parse a single field (for OBJECT, INTERFACE, or INPUT_OBJECT)
// ------------------------------------------------------------------
static FieldInfo* parse_field(cJSON *field_json) {
    FieldInfo *fi = calloc(1, sizeof(FieldInfo));
    if (!fi) return NULL;

    cJSON *name = cJSON_GetObjectItem(field_json, "name");
    if (name && name->valuestring) fi->name = strdup(name->valuestring);

    // Arguments
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

    // Return type
    cJSON *type = cJSON_GetObjectItem(field_json, "type");
    if (type) {
        char type_buf[256] = {0};
        append_type_string(type, type_buf);
        fi->type_string = strdup(type_buf);
    }

    // Deprecated
    cJSON *dep = cJSON_GetObjectItem(field_json, "isDeprecated");
    fi->is_deprecated = (dep && dep->type == cJSON_True);

    // Default value (for input fields)
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
// Parse a single type (including fields, enum values, etc.)
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

    // OBJECT and INTERFACE: fields
    if (strcmp(kind_str, "OBJECT") == 0 || strcmp(kind_str, "INTERFACE") == 0) {
        cJSON *fields = cJSON_GetObjectItem(type_json, "fields");
        if (fields) {
            int count = cJSON_GetArraySize(fields);
            t->num_fields = count;
            if (count > 0) {
                t->fields = calloc(count, sizeof(FieldInfo));
                for (int i = 0; i < count; i++) {
                    cJSON *field_json = cJSON_GetArrayItem(fields, i);
                    t->fields[i] = *parse_field(field_json); // shallow copy; we'll manage memory in free
                }
            }
        }

        // Interfaces (only for OBJECT)
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
    // ENUM
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
    // INPUT_OBJECT
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
    // UNION
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
    // SCALAR
    else if (strcmp(kind_str, "SCALAR") == 0) {
        cJSON *spec_url = cJSON_GetObjectItem(type_json, "specifiedByURL");
        if (spec_url && spec_url->valuestring) {
            t->specified_by_url = strdup(spec_url->valuestring);
        }
    }

    return t;
}

// ------------------------------------------------------------------
// Build the complete schema data from JSON root
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

    // Helper to find a type by name
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

    // Root operations
    cJSON *query_type = cJSON_GetObjectItem(schema, "queryType");
    cJSON *mutation_type = cJSON_GetObjectItem(schema, "mutationType");
    cJSON *subscription_type = cJSON_GetObjectItem(schema, "subscriptionType");

    if (query_type) {
        cJSON *qname = cJSON_GetObjectItem(query_type, "name");
        if (qname && qname->valuestring) {
            cJSON *qobj = find_type_json_by_name(types, qname->valuestring);
            if (qobj) {
                sdata->query_type = parse_type(qobj);
            }
        }
    }

    if (mutation_type) {
        cJSON *mname = cJSON_GetObjectItem(mutation_type, "name");
        if (mname && mname->valuestring) {
            cJSON *mobj = find_type_json_by_name(types, mname->valuestring);
            if (mobj) {
                sdata->mutation_type = parse_type(mobj);
            }
        }
    }

    if (subscription_type) {
        cJSON *sname = cJSON_GetObjectItem(subscription_type, "name");
        if (sname && sname->valuestring) {
            cJSON *sobj = find_type_json_by_name(types, sname->valuestring);
            if (sobj) {
                sdata->subscription_type = parse_type(sobj);
            }
        }
    }

    // Collect all custom types (skip built-in scalars and __* types)
    int total_types = cJSON_GetArraySize(types);
    int custom_count = 0;
    // First pass: count custom types
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

    // Directives
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
// Print a field from FieldInfo
// ------------------------------------------------------------------
static void print_field_info(FieldInfo *field, int indent) {
    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s", field->name);

    // Arguments
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
    if (field->is_deprecated) printf(" [DEPRECATED]");
    if (field->default_value) printf(" = %s", field->default_value);
    printf("\n");
}

// ------------------------------------------------------------------
// Print a type from TypeInfo
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
        // Fields
        for (int i = 0; i < type->num_fields; i++) {
            print_field_info(&type->fields[i], indent + 1);
        }
        // Interfaces (only OBJECT)
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
            if (type->enum_values[i].is_deprecated) printf(" [DEPRECATED]");
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
// Print the entire schema from SchemaData
// ------------------------------------------------------------------
static void print_schema_data(SchemaData *schema) {
    if (!schema) return;

    printf("\n========== GRAPHQL SCHEMA ANALYSIS (STRUCT-BASED) ==========\n\n");

    // Root operations
    if (schema->query_type) {
        printf("🔍 ROOT QUERY:\n");
        print_type_info(schema->query_type, 0);
    }
    if (schema->mutation_type) {
        printf("ROOT MUTATION:\n");
        print_type_info(schema->mutation_type, 0);
    } else {
        printf("ROOT MUTATION: (none)\n\n");
    }
    if (schema->subscription_type) {
        printf("📡 ROOT SUBSCRIPTION:\n");
        print_type_info(schema->subscription_type, 0);
    } else {
        printf("📡 ROOT SUBSCRIPTION: (none)\n\n");
    }

    // All custom types
    printf("ALL CUSTOM TYPES (objects, enums, scalars, unions, interfaces, input objects):\n\n");
    for (int i = 0; i < schema->num_types; i++) {
        print_type_info(schema->types[i], 0);
    }

    // Directives
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

    // Summary (counts are already in the struct, but we can compute)
    int total_types = schema->num_types;
    int builtin = 0;
    // We don't have built-in count in struct, but we can compute from original idea; skip for brevity.
    printf("SUMMARY:\n");
    printf("  - Custom types: %d\n", total_types);
    printf("  - Directives: %d\n", schema->num_directives);
    // Additional summary can be added if needed.
}

// ------------------------------------------------------------------
// Free all allocated memory in a FieldInfo
// ------------------------------------------------------------------
static void free_field_info(FieldInfo *fi) {
    if (!fi) return;
    free(fi->name);
    for (int i = 0; i < fi->num_args; i++) {
        free(fi->args[i].name);
        free(fi->args[i].type_string);
    }
    free(fi->args);
    free(fi->type_string);
    free(fi->default_value);
}

// ------------------------------------------------------------------
// Free an EnumValueInfo
// ------------------------------------------------------------------
static void free_enum_value_info(EnumValueInfo *ev) {
    if (!ev) return;
    free(ev->name);
}

// ------------------------------------------------------------------
// Free a TypeInfo completely
// ------------------------------------------------------------------
static void free_type_info(TypeInfo *t) {
    if (!t) return;
    free(t->name);
    free(t->kind);
    free(t->description);
    for (int i = 0; i < t->num_fields; i++) {
        free_field_info(&t->fields[i]);
    }
    free(t->fields);
    for (int i = 0; i < t->num_interfaces; i++) {
        free(t->interfaces[i]);
    }
    free(t->interfaces);
    for (int i = 0; i < t->num_enum_values; i++) {
        free_enum_value_info(&t->enum_values[i]);
    }
    free(t->enum_values);
    for (int i = 0; i < t->num_input_fields; i++) {
        free_field_info(&t->input_fields[i]);
    }
    free(t->input_fields);
    for (int i = 0; i < t->num_possible_types; i++) {
        free(t->possible_types[i]);
    }
    free(t->possible_types);
    free(t->specified_by_url);
    free(t);
}

// ------------------------------------------------------------------
// Free the entire SchemaData
// ------------------------------------------------------------------
static void free_schema_data(SchemaData *schema) {
    if (!schema) return;
    free_type_info(schema->query_type);
    free_type_info(schema->mutation_type);
    free_type_info(schema->subscription_type);
    for (int i = 0; i < schema->num_types; i++) {
        free_type_info(schema->types[i]);
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

// ------------------------------------------------------------------
// Main analysis entry point (kept same name and signature as original)
// ------------------------------------------------------------------
int inrropection_check(char *intro_json) {
    FILE *file = fopen(intro_json, "rb");
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = (char *)malloc(length + 1);
    if (!data) {
        perror("Memory allocation failed");
        fclose(file);
        return 1;
    }

    size_t read_len = fread(data, 1, length, file);
    if (read_len != (size_t)length) {
        perror("Read error");
        free(data);
        fclose(file);
        return 1;
    }
    data[length] = '\0';
    fclose(file);

    cJSON *json = cJSON_Parse(data);
    free(data);

    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON Parse Error: %s\n", error_ptr);
        }
        return 1;
    }

    // Build schema data
    SchemaData *schema = build_schema_data(json);
    if (schema) {
        // Print from the structs
        print_schema_data(schema);
        // Free all memory
        free_schema_data(schema);
    }

    cJSON_Delete(json);
    return 0;
}


int detect_graphql(char *full_path){
    request r = {0};


    FILE *f = fopen("glassworm/graphql/uni.json", "r");
    if (!f) {
        fprintf(stderr, "Failed to open uni.json\n");
        return;
    }

    // Read the JSON content from the file
    fseek(f, 0, SEEK_END);
    long json_size = ftell(f);
    rewind(f);

    char *json = malloc(json_size + 1);
    if (!json) {
        fprintf(stderr, "Failed to allocate memory for JSON content\n");
        fclose(f);
        return;
    }

    if (fread(json, 1, json_size, f) != json_size) {
        fprintf(stderr, "Failed to read JSON content\n");
        free(json);
        fclose(f);
        return;
    }
    json[json_size] = '\0';
    fclose(f);

    FILE *api = fopen(full_path, "r");
    
    if (!api) {
        fprintf(stderr, "Failed to open api.txt\n");
        free(json);
        return;
    }
    char api_url[256];

    while (fgets(api_url, sizeof(api_url), api)) {
        http_send_post(
            &r,
            api_url,
            false,       // upload = false
            NULL,
            true,        // is_raw = true
            json
        );

        if (r.code != 200) {
            fprintf(stderr, "Failed to send GraphQL request\n");
            return 1;
        }

        FILE *fp = fopen(r.filename, "r");
        fseek(fp, 0, SEEK_END);
        long needle_size = ftell(f);
        rewind(f);

        char *needle = malloc(needle_size + 1);
        if (!needle) {
            fprintf(stderr, "Failed to allocate memory for JSON content\n");
            fclose(f);
            return;
        }

        if (fread(needle, 1, needle_size, fp) != needle_size) {
            fprintf(stderr, "Failed to read JSON content\n");
            free(needle);
            fclose(f);
            return;
        }
        needle[needle_size] = '\0';

        fclose(f);

        char *result_one = strstr("__schema", needle);
        char *result_two = strstr("\"data\"", needle);
        char *result_three = strstr("\"errors\"", needle);
        char *result_four = strstr("\"query\"", needle);

        if (result_one || result_two || result_three || result_four) {
         printf("GraphQL detected\n");
            return 1;
        } else {
            printf("GraphQL not detected\n");
            return 0;
        }
        free(needle);
    }

   
    free(json);
}

int graphql_scanning(char *path) {

    // get gobuster.txt data
    char gobuster_path[256];
    snprintf(gobuster_path, sizeof(gobuster_path), "%s/gobuster.txt", path);
    FILE *gobuster_file = fopen(gobuster_path, "r");
    if (!gobuster_file) {
        fprintf(stderr, "Failed to open gobuster.txt\n");
        return 1;
    }
    char gobuster_url[512];

    // api.txt
    char api_path[256];
    snprintf(api_path,"%s/api.txt", path);
    FILE *api_file = fopen(api_path, "w");
    if (!api_file) {
        fprintf(stderr, "Failed to open api.txt\n");
        fclose(gobuster_file);
        return 1;
    }

    while(fgets(gobuster_url, sizeof(gobuster_url), gobuster_file)) {
        if (scanf(gobuster_url, "graphql") == 0) {
            fprintf(stderr, "Failed to parse URL from gobuster.txt\n");
            fprintf(api_file, "%s", gobuster_url);
        }
        if (scanf(gobuster_url, "api") == 0) {
            fprintf(stderr, "Failed to parse URL from gobuster.txt\n");
            fprintf(api_file, "%s", gobuster_url);
        }

    }
    if (detect_graphql(api_path) == 1) {
        printf("[+] GraphQL detected\n");
    } else {
        printf("[-] GraphQL not detected\n");
    }
}

