#ifndef _NGX_HTTP_XSLTPROC_FILTER_MODULE_H_INCLUDED_
#define _NGX_HTTP_XSLTPROC_FILTER_MODULE_H_INCLUDED_

#ifndef NGX_HTTP_XSLTPROC_REUSE_DTD
#define NGX_HTTP_XSLTPROC_REUSE_DTD  1
#endif

typedef struct {
    u_char              *name;
    void                *data;
} ngx_http_xsltproc_file_t;


typedef struct {
    ngx_array_t          dtd_files;    /* ngx_http_xsltproc_file_t */
    ngx_array_t          sheet_files;  /* ngx_http_xsltproc_file_t */

    ngx_array_t          sheet_cache;  /* ngx_http_xsltproc_file_t */
    ngx_pool_t          *pool;
} ngx_http_xsltproc_filter_main_conf_t;


typedef struct {
    xsltStylesheetPtr    stylesheet;
    ngx_array_t          params;       /* ngx_http_complex_value_t */
} ngx_http_xsltproc_sheet_t;


typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           cache_enable;
    
    xmlDtdPtr            dtd;
    ngx_array_t          sheets;       /* ngx_http_xsltproc_sheet_t */
    ngx_hash_t           types;
    ngx_array_t         *types_keys;
} ngx_http_xsltproc_filter_loc_conf_t;


typedef struct {
    xmlDocPtr            doc;
    xmlParserCtxtPtr     ctxt;
    ngx_http_request_t  *request;
    ngx_array_t          params;
    ngx_array_t          sheets;       /* ngx_http_xsltproc_sheet_t */

    ngx_uint_t           done;         /* unsigned  done:1; */
} ngx_http_xsltproc_filter_ctx_t;


static ngx_int_t ngx_http_xsltproc_parse_stylesheet(ngx_http_request_t *r,
    ngx_http_xsltproc_filter_ctx_t *ctx, u_char *name,
    xsltStylesheetPtr *stylesheet);
static ngx_int_t ngx_http_xsltproc_parse_params(ngx_http_request_t *r, ngx_array_t *params);
static ngx_int_t ngx_http_xsltproc_parse_header(ngx_http_request_t *r, ngx_http_xsltproc_filter_ctx_t *ctx);
static ngx_int_t ngx_http_xsltproc_header_filter(ngx_http_request_t *r);

static ngx_int_t ngx_http_xsltproc_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_xsltproc_send(ngx_http_request_t *r, ngx_http_xsltproc_filter_ctx_t *ctx,
    ngx_buf_t *b);
static ngx_int_t ngx_http_xsltproc_add_chunk(ngx_http_request_t *r, ngx_http_xsltproc_filter_ctx_t *ctx,
    ngx_buf_t *b);
static void ngx_http_xsltproc_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId);
static void ngx_cdecl ngx_http_xsltproc_sax_error(void *data, const char *msg, ...);
static ngx_buf_t * ngx_http_xsltproc_apply_stylesheet(ngx_http_request_t *r,
    ngx_http_xsltproc_filter_ctx_t *ctx);

static ngx_int_t ngx_http_xsltproc_params(ngx_http_request_t *r, ngx_http_xsltproc_filter_ctx_t *ctx,
    ngx_array_t *params);
static u_char * ngx_http_xsltproc_content_type(xsltStylesheetPtr s);

static u_char * ngx_http_xsltproc_encoding(xsltStylesheetPtr s);

static void ngx_http_xsltproc_cleanup(void *data);

static char * ngx_http_xsltproc_entities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_xsltproc_stylesheet(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_xsltproc_cleanup_dtd(void *data);

static void ngx_http_xsltproc_cleanup_stylesheet(void *data);

static void * ngx_http_xsltproc_filter_create_main_conf(ngx_conf_t *cf);
static void * ngx_http_xsltproc_filter_create_conf(ngx_conf_t *cf);
static char * ngx_http_xsltproc_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_xsltproc_filter_init(ngx_conf_t *cf);
static void ngx_http_xsltproc_filter_exit(ngx_cycle_t *cycle);

static u_char ngx_http_xsltproc_empty_xpath_expression[] = "''\0";

ngx_str_t  ngx_http_xsltproc_default_types[] = {
    ngx_string("text/xml"),
    ngx_null_string
};


static ngx_command_t  ngx_http_xsltproc_filter_commands[] = {

    { ngx_string("xsltproc"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xsltproc_filter_loc_conf_t, enable),
      NULL },

    { ngx_string("xsltproc_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xsltproc_filter_loc_conf_t, cache_enable),
      NULL },

    { ngx_string("xmlproc_entities"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xsltproc_entities,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xsltproc_stylesheet"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_xsltproc_stylesheet,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xsltproc_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xsltproc_filter_loc_conf_t, types_keys),
      &ngx_http_xsltproc_default_types[0] },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_xsltproc_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_xsltproc_filter_init,         /* postconfiguration */

    ngx_http_xsltproc_filter_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_xsltproc_filter_create_conf,  /* create location configuration */
    ngx_http_xsltproc_filter_merge_conf    /* merge location configuration */
};


ngx_module_t ngx_http_xsltproc_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_xsltproc_filter_module_ctx,  /* module context */
    ngx_http_xsltproc_filter_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_xsltproc_filter_exit,         /* exit process */
    ngx_http_xsltproc_filter_exit,         /* exit master */
    NGX_MODULE_V1_PADDING
};

#endif
