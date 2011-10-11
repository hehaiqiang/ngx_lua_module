
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_axis2c.h>


static int ngx_lua_webservice_parse(lua_State *l);
static void ngx_lua_webservice_parse_children(lua_State *l, axutil_env_t *env,
    axiom_node_t *parent, axiom_element_t *parent_elem);

static int ngx_lua_webservice_serialize(lua_State *l);
static void ngx_lua_webservice_serialize_tables(lua_State *l, axutil_env_t *env,
    axiom_node_t *parent);
static void ngx_lua_webservice_serialize_table(lua_State *l, axutil_env_t *env,
    axiom_node_t *parent, char *name, int index);

static ngx_int_t ngx_lua_webservice_module_init(ngx_cycle_t *cycle);


static ngx_lua_const_t  ngx_lua_webservice_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_webservice_methods[] = {
    { "parse", ngx_lua_webservice_parse },
    { "serialize", ngx_lua_webservice_serialize },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_webservice_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_webservice_module_init,        /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_LUA_DLL)
ngx_module_t **
ngx_lua_get_modules(void)
{
    static ngx_module_t  *modules[] = {
        &ngx_lua_webservice_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_webservice_parse(lua_State *l)
{
    char                   *uri, *prefix, *name;
    ngx_str_t               soap;
    axiom_node_t           *node;
    axutil_env_t           *env;
    axutil_log_t           *log;
    axutil_error_t         *error;
    axiom_element_t        *elem;
    ngx_lua_thread_t       *thr;
    axiom_namespace_t      *ns;
    axiom_soap_body_t      *body;
    axutil_allocator_t     *a;
    axiom_xml_reader_t     *reader;
    axiom_soap_header_t    *header;
    axiom_stax_builder_t   *builder;
    axiom_soap_builder_t   *soap_builder;
    axiom_soap_envelope_t  *envelope;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua webservice parse");

    soap.data = (u_char *) luaL_checklstring(l, 1, &soap.len);

    lua_createtable(l, 2, 2);

    a = ngx_lua_axis2c_allocator_create(thr);
    log = ngx_lua_axis2c_log_create(thr);
    error = axutil_error_create(a);
    env = axutil_env_create_with_error_log(a, error, log);

    reader = axiom_xml_reader_create_for_memory(env, soap.data, soap.len, NULL,
                                                AXIS2_XML_PARSER_TYPE_BUFFER);
    builder = axiom_stax_builder_create(env, reader);
    soap_builder = axiom_soap_builder_create(env, builder,
                                      AXIOM_SOAP12_SOAP_ENVELOPE_NAMESPACE_URI);
    envelope = axiom_soap_builder_get_soap_envelope(soap_builder, env);

    ns = axiom_soap_envelope_get_namespace(envelope, env);
    if (ns != NULL) {
        uri = axiom_namespace_get_uri(ns, env);
        if (uri != NULL) {
            lua_pushstring(l, uri);
            lua_setfield(l, -2, "uri");
        }

        prefix = axiom_namespace_get_prefix(ns, env);
        if (prefix != NULL) {
            lua_pushstring(l, prefix);
            lua_setfield(l, -2, "prefix");
        }
    }

    header = axiom_soap_envelope_get_header(envelope, env);
    if (header != NULL) {
        node = axiom_soap_header_get_base_node(header, env);
        elem = axiom_node_get_data_element(node, env);

        /* TODO */

        lua_newtable(l);

        ngx_lua_webservice_parse_children(l, env, node, elem);

        lua_setfield(l, -2, "header");
    }

    body = axiom_soap_envelope_get_body(envelope, env);
    if (body != NULL) {

        /* TODO: axiom_soap_body_has_fault */
        /* TODO: axiom_soap_body_get_fault */

        node = axiom_soap_body_get_base_node(body, env);
        if (node == NULL) {
            return 1;
        }

        if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT) {
            return 1;
        }

        elem = axiom_node_get_data_element(node, env);
        name = axiom_element_get_localname(elem, env);

        if (ngx_strcmp(name, "Body") != 0) {
            return 1;
        }

        lua_newtable(l);

        ngx_lua_webservice_parse_children(l, env, node, elem);

        lua_setfield(l, -2, "body");
    }

    return 1;
}


static void
ngx_lua_webservice_parse_children(lua_State *l, axutil_env_t *env,
    axiom_node_t *parent, axiom_element_t *parent_elem)
{
    int                              n;
    char                            *uri, *prefix, *name, *text;
    axiom_node_t                    *node;
    axutil_hash_t                   *attrs;
    axiom_element_t                 *elem;
    ngx_lua_thread_t                *thr;
    axiom_attribute_t               *attr;
    axiom_namespace_t               *ns;
    axutil_hash_index_t             *hi;
    axiom_child_element_iterator_t  *it;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua webservice parse children");

    it = axiom_element_get_child_elements(parent_elem, env, parent);
    if (it == NULL) {
        return;
    }

    n = 1;

    do {

        node = axiom_child_element_iterator_next(it, env);
        elem = axiom_node_get_data_element(node, env);
        name = axiom_element_get_localname(elem, env);

        lua_createtable(l, 2, 4);

        lua_pushstring(l, name);
        lua_setfield(l, -2, "name");

        ns = axiom_element_get_namespace(elem, env, node);
        if (ns != NULL) {
            uri = axiom_namespace_get_uri(ns, env);
            if (uri != NULL) {
                lua_pushstring(l, uri);
                lua_setfield(l, -2, "uri");
            }

            prefix = axiom_namespace_get_prefix(ns, env);
            if (prefix != NULL) {
                lua_pushstring(l, prefix);
                lua_setfield(l, -2, "prefix");
            }
        }

        attrs = axiom_element_get_all_attributes(elem, env);
        if (attrs != NULL) {
            lua_newtable(l);

            hi = axutil_hash_first(attrs, env);

            do {
                if (hi == NULL) {
                    break;
                }

                axutil_hash_this(hi, NULL, NULL, (void **) &attr);

                lua_pushstring(l, axiom_attribute_get_value(attr, env));
                lua_setfield(l, -2, axiom_attribute_get_localname(attr, env));

                hi = axutil_hash_next(env, hi);
            } while (1);

            lua_setfield(l, -2, "attributes");
        }

        text = axiom_element_get_text(elem, env, node);
        if (text != NULL) {
            lua_pushstring(l, text);
            lua_setfield(l, -2, "text");

        } else {
            lua_newtable(l);

            ngx_lua_webservice_parse_children(l, env, node, elem);

            lua_setfield(l, -2, "children");
        }

        lua_setfield(l, -2, name);

        lua_getfield(l, -1, name);
        lua_rawseti(l, -2, n++);

    } while (axiom_child_element_iterator_has_next(it, env) == AXIS2_TRUE);
}


static int
ngx_lua_webservice_serialize(lua_State *l)
{
    int                     top;
    char                   *uri, *prefix;
    axiom_node_t           *node;
    axutil_env_t           *env;
    axutil_log_t           *log;
    axutil_error_t         *error;
    axiom_output_t         *output;
    ngx_lua_thread_t       *thr;
    axiom_namespace_t      *ns;
    axiom_soap_body_t      *body;
    axutil_allocator_t     *a;
    axiom_xml_writer_t     *writer;
    axiom_soap_header_t    *header;
    axiom_soap_envelope_t  *envelope;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua webservice serialize");

    top = lua_gettop(l);

    if (!lua_istable(l, top)) {
        return luaL_error(l, "invalid argument, must be a table");
    }

    a = ngx_lua_axis2c_allocator_create(thr);
    log = ngx_lua_axis2c_log_create(thr);
    error = axutil_error_create(a);
    env = axutil_env_create_with_error_log(a, error, log);

    lua_getfield(l, top, "uri");
    uri = (char *) luaL_optstring(l, -1,
                                  "http://www.w3.org/2003/05/soap-envelope");

    lua_getfield(l, top, "prefix");
    prefix = (char *) luaL_optstring(l, -1, "soap");

    ns = axiom_namespace_create(env, uri, prefix);
    envelope = axiom_soap_envelope_create(env, ns);

    lua_getfield(l, top, "header");
    if (!lua_isnil(l, -1)) {
        if (!lua_istable(l, -1)) {
            return luaL_error(l, "the value of \"header\" must be a table");
        }

        header = axiom_soap_header_create_with_parent(env, envelope);
        node = axiom_soap_header_get_base_node(header, env);

        ngx_lua_webservice_serialize_tables(l, env, node);
    }

    lua_getfield(l, top, "body");
    if (!lua_isnil(l, -1)) {
        if (!lua_istable(l, -1)) {
            return luaL_error(l, "the value of \"body\" must be a table");
        }

        body = axiom_soap_body_create_with_parent(env, envelope);
        node = axiom_soap_body_get_base_node(body, env);

        ngx_lua_webservice_serialize_tables(l, env, node);
    }

    lua_settop(l, top);

    writer = axiom_xml_writer_create_for_memory(env, NULL, AXIS2_FALSE,
                                                AXIS2_FALSE,
                                                AXIS2_XML_PARSER_TYPE_BUFFER);
    output = axiom_output_create(env, writer);
    axiom_soap_envelope_serialize(envelope, env, output, AXIS2_FALSE);

    lua_pushstring(l, axiom_xml_writer_get_xml(writer, env));

    return 1;
}


static void
ngx_lua_webservice_serialize_tables(lua_State *l, axutil_env_t *env,
    axiom_node_t *parent)
{
    int                type, n, i, index;
    char              *name;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua webservice serialize tables");

    lua_pushnil(l);

    while (lua_next(l, -2)) {
        type = lua_type(l, -2);
        if (type == LUA_TNUMBER) {
            lua_pop(l, 1);
            continue;
        }

        name = (char *) luaL_checkstring(l, -2);

        if (!lua_istable(l, -1)) {
            luaL_error(l, "the value of \"%s\" must be a table", name);
        }

        index = lua_gettop(l);

        ngx_lua_webservice_serialize_table(l, env, parent, name, index);

        lua_pop(l, 1);
    }

    n = lua_objlen(l, -1);

    for (i = 1; i <= n; i++) {
        lua_rawgeti(l, -1, i);

        /* TODO */

        if (!lua_istable(l, -1)) {
            luaL_error(l, "must be a table");
        }

        lua_getfield(l, -1, "name");
        name = (char *) luaL_checkstring(l, -1);

        index = lua_gettop(l) - 1;

        ngx_lua_webservice_serialize_table(l, env, parent, name, index);

        lua_pop(l, 2);
    }
}


static void
ngx_lua_webservice_serialize_table(lua_State *l, axutil_env_t *env,
    axiom_node_t *parent, char *name, int index)
{
    int                 top;
    char               *uri, *prefix, *text, *value;
    axiom_node_t       *node;
    axiom_element_t    *elem;
    ngx_lua_thread_t   *thr;
    axiom_namespace_t  *ns;
    axiom_attribute_t  *attr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua webservice serialize table");

    top = lua_gettop(l);

    lua_getfield(l, index, "uri");
    uri = (char *) luaL_optstring(l, -1, NULL);

    lua_getfield(l, index, "prefix");
    prefix = (char *) luaL_optstring(l, -1, NULL);

    if (uri != NULL || prefix != NULL) {
        ns = axiom_namespace_create(env, uri, prefix);

    } else {
        ns = NULL;
    }

    elem = axiom_element_create(env, parent, name, ns, &node);

    lua_getfield(l, index, "attributes");
    if (!lua_isnil(l, -1)) {
        if (!lua_istable(l, -1)) {
            luaL_error(l, "the value of \"attributes\" must be a table");
        }

        lua_pushnil(l);

        while (lua_next(l, -2)) {
            name = (char *) luaL_checkstring(l, -2);
            value = (char *) luaL_checkstring(l, -1);

            attr = axiom_attribute_create(env, name, value, NULL);
            axiom_element_add_attribute(elem, env, attr, node);

            lua_pop(l, 1);
        }
    }

    lua_getfield(l, index, "text");
    text = (char *) luaL_optstring(l, -1, NULL);

    if (text != NULL) {
        axiom_element_set_text(elem, env, text, node);
        lua_settop(l, top);
        return;
    }

    lua_getfield(l, index, "children");
    if (!lua_isnil(l, -1)) {
        if (!lua_istable(l, -1)) {
            luaL_error(l, "the value of \"children\" must be a table");
        }

        ngx_lua_webservice_serialize_tables(l, env, node);
    }

    lua_settop(l, top);
}


static ngx_int_t
ngx_lua_webservice_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua webservice module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, "nginx");

    n = sizeof(ngx_lua_webservice_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_webservice_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_webservice_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_webservice_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_webservice_consts[n].name);
    }

    for (n = 0; ngx_lua_webservice_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_webservice_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_webservice_methods[n].name);
    }

    lua_setfield(lcf->l, -2, "webservice");

    lua_pop(lcf->l, 1);

#if 0
    axutil_error_init();
#endif

    return NGX_OK;
}
