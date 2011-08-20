
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>

#undef S_IWRITE

#include <axis2_util.h>
#include <axutil_error_default.h>
#include <axiom.h>
#include <axiom_soap.h>


typedef struct {
    axutil_allocator_t     allocator;
    ngx_http_request_t    *r;
} ngx_lua_axis2c_allocator_t;


static int ngx_lua_axis2c_parse(lua_State *l);
static int ngx_lua_axis2c_serialize(lua_State *l);

static axutil_allocator_t *ngx_lua_axis2c_allocator_create(
    ngx_http_request_t *r);
static void *__stdcall ngx_lua_axis2c_allocator_malloc(
    axutil_allocator_t *allocator, size_t size);
static void *__stdcall ngx_lua_axis2c_allocator_realloc(
    axutil_allocator_t *allocator, void *ptr, size_t size);
static void __stdcall ngx_lua_axis2c_allocator_free(
    axutil_allocator_t *allocator, void *ptr);

static axutil_log_t *ngx_lua_axis2c_log_create(ngx_http_request_t *r);


static ngx_lua_const_t  ngx_lua_axis2c_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_axis2c_methods[] = {
    { "parse", ngx_lua_axis2c_parse },
    { "serialize", ngx_lua_axis2c_serialize },
    { NULL, NULL }
};


void
ngx_lua_axis2c_api_init(lua_State *l)
{
    int  n;

    n = sizeof(ngx_lua_axis2c_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_axis2c_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(l, 0, n);

    for (n = 0; ngx_lua_axis2c_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_axis2c_consts[n].value);
        lua_setfield(l, -2, ngx_lua_axis2c_consts[n].name);
    }

    for (n = 0; ngx_lua_axis2c_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_axis2c_methods[n].func);
        lua_setfield(l, -2, ngx_lua_axis2c_methods[n].name);
    }

    lua_setfield(l, -2, "axis2c");
}


static int
ngx_lua_axis2c_parse(lua_State *l)
{
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    /* TODO */

    return 0;
}


static int
ngx_lua_axis2c_serialize(lua_State *l)
{
    axutil_allocator_t  *a;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    a = ngx_lua_axis2c_allocator_create(r);
    if (a == NULL) {
        return luaL_error(l, "ngx_lua_axis2c_allocator_create() failed");
    }

    /* TODO */

#if 0
    axiom_node_t        *node;
    axutil_env_t        *env;
    axutil_log_t        *log;
    axutil_error_t      *error;
    axutil_allocator_t  *allocator;

    allocator = axutil_allocator_init(NULL);

    log = axutil_log_create(allocator, NULL, "test_soap.log");
    log->level = AXIS2_LOG_LEVEL_DEBUG;

    error = axutil_error_create(allocator);
    env = axutil_env_create_with_error_log(allocator, error, log);

    axutil_error_init();

    axis2_char_t           *buffer;
    axiom_node_t           *node, *child;
    axiom_output_t         *output;
    axiom_namespace_t      *ns;
    axiom_soap_body_t      *body;
    axiom_xml_writer_t     *writer;
    axiom_soap_envelope_t  *envelope;

    ns = axiom_namespace_create(env, "http://www.w3.org/2003/05/soap-envelope", "soap");
    envelope = axiom_soap_envelope_create(env, ns);
    body = axiom_soap_body_create_with_parent(env, envelope);

    node = axiom_node_create(env);
    ns = axiom_namespace_create(env, "http://www.onvif.org/ver10/device/wsdl", "tds");
    axiom_element_create(env, node, "SystemReboot", ns, &child);

    axiom_soap_body_add_child(body, env, node);

    writer = axiom_xml_writer_create_for_memory(env, NULL, AXIS2_FALSE, AXIS2_FALSE, AXIS2_XML_PARSER_TYPE_BUFFER);
    output = axiom_output_create(env, writer);
    axiom_soap_envelope_serialize(envelope, env, output, AXIS2_FALSE);
    buffer = axiom_xml_writer_get_xml(writer, env);

    printf("%s\n\n", buffer);

    axiom_xml_writer_free(writer, env);
    axiom_soap_envelope_free(envelope, env);

    axutil_env_free(env);
#endif

    return 0;
}


static axutil_allocator_t *
ngx_lua_axis2c_allocator_create(ngx_http_request_t *r)
{
    ngx_lua_axis2c_allocator_t  *a;

    a = ngx_pcalloc(r->pool, sizeof(ngx_lua_axis2c_allocator_t));
    if (a == NULL) {
        return NULL;
    }

    a->allocator.malloc_fn = ngx_lua_axis2c_allocator_malloc;
    a->allocator.realloc = ngx_lua_axis2c_allocator_realloc;
    a->allocator.free_fn = ngx_lua_axis2c_allocator_free;

    a->r = r;

    return &a->allocator;
}


static void *__stdcall
ngx_lua_axis2c_allocator_malloc(axutil_allocator_t *allocator, size_t size)
{
    /* TODO */

    return NULL;
}


static void *__stdcall
ngx_lua_axis2c_allocator_realloc(axutil_allocator_t *allocator, void *ptr,
    size_t size)
{
    /* TODO */

    return NULL;
}


static void __stdcall
ngx_lua_axis2c_allocator_free(axutil_allocator_t *allocator, void *ptr)
{
}
