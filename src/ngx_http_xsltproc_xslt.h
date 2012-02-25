#ifndef _NGX_HTTP_XSLTPROC_XSLT_H_INCLUDED_
#define _NGX_HTTP_XSLTPROC_XSLT_H_INCLUDED_

#ifndef NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING
#define NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING  1
#endif

#ifndef NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING
#define NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING  1
#endif

#define XSLT_KEYS_LIST_FREE_NONE 0
#define XSLT_KEYS_LIST_FREE_DATA 1
#define XSLT_KEYS_LIST_FREE_KEYS 2

typedef struct {
    ngx_http_xsltproc_list_t  list;
    char                     *uri;
    xsltStylesheetPtr         stylesheet;
    xsltDocumentPtr           doc_list;
    time_t                    mtime;
} ngx_http_xsltproc_xslt_stylesheet_t;

typedef struct {
    ngx_http_xsltproc_list_t  list;
    char                     *uri;
    xmlDocPtr                 doc;
} ngx_http_xsltproc_xslt_document_t;

typedef struct {
    time_t mtime;
} ngx_http_xsltproc_xml_document_extra_info_t;

typedef struct {
    ngx_http_xsltproc_list_t  list;
    char                     *stylesheet_uri;
    time_t                    stylesheet_mtime;
    char                     *document_uri;
    time_t                    document_mtime;
    xsltDocumentPtr           xslt_document;
} ngx_http_xsltproc_xslt_keys_t;

/* ngx_http_xsltproc_xslt */
xmlDocPtr ngx_http_xsltproc_xslt_transform(
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet, xmlDocPtr doc,
    const char **params, xmlDocPtr *profile_info);
int ngx_http_xsltproc_xslt_output(char **buf, int *buf_len, xmlDocPtr result,
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet);
void ngx_http_xsltproc_xslt_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_cleanup(void);

/* ngx_http_xsltproc_xslt_document_cache */
ngx_http_xsltproc_xslt_document_t *ngx_http_xsltproc_xslt_document_cache_lookup(char *uri);
int ngx_http_xsltproc_xslt_document_cache_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_document_cache_destroy(void);
void ngx_http_xsltproc_xslt_document_cache_clean(void);

/* ngx_http_xsltproc_xslt_document */
ngx_http_xsltproc_xslt_document_t *ngx_http_xsltproc_xslt_document_new(char *uri);
int ngx_http_xsltproc_xslt_document_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_document_destroy(void);
int ngx_http_xsltproc_xslt_document_is_updated(ngx_http_xsltproc_xslt_document_t *xslt_document);
void ngx_http_xsltproc_xslt_document_clear(ngx_http_xsltproc_xslt_document_t *xslt_document);
void ngx_http_xsltproc_xslt_document_free(ngx_http_xsltproc_xslt_document_t *xslt_document);

/* ngx_http_xsltproc_xslt_stylesheet_cache */
int ngx_http_xsltproc_xslt_stylesheet_cache_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_stylesheet_cache_destroy(void);
ngx_http_xsltproc_xslt_stylesheet_t *
ngx_http_xsltproc_xslt_stylesheet_cache_lookup(ngx_http_xsltproc_filter_loc_conf_t *cf, char *uri);
void ngx_http_xsltproc_xslt_stylesheet_cache_clean(void);

/* ngx_http_xsltproc_xslt_stylesheet */
ngx_http_xsltproc_xslt_stylesheet_t *ngx_http_xsltproc_xslt_stylesheet_new(char *uri);
ngx_http_xsltproc_xslt_stylesheet_t
*ngx_http_xsltproc_xslt_stylesheet_parse_file(ngx_http_xsltproc_filter_loc_conf_t *cf, char *uri);
int ngx_http_xsltproc_xslt_stylesheet_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_stylesheet_destroy(void);
void ngx_http_xsltproc_xslt_stylesheet_restore_documents(
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet, xsltTransformContextPtr ctxt);
void ngx_http_xsltproc_xslt_stylesheet_backup_documents(
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet, xsltTransformContextPtr ctxt);
void ngx_http_xsltproc_xslt_stylesheet_free_documents(xsltDocumentPtr doc_list);
void ngx_http_xsltproc_xslt_stylesheet_free(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet);
void ngx_http_xsltproc_xslt_stylesheet_clear(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet);
int ngx_http_xsltproc_xslt_stylesheet_is_updated(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet);

/* ngx_http_xsltproc_xslt_keys */
int ngx_http_xsltproc_xslt_keys_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_keys_destroy(void);
ngx_http_xsltproc_xslt_keys_t *ngx_http_xsltproc_xslt_keys_new(char *stylesheet_uri,
    time_t stylesheet_mtime, char *document_uri, time_t document_mtime, xsltDocumentPtr xslt_document);
void ngx_http_xsltproc_xslt_keys_free(ngx_http_xsltproc_xslt_keys_t *xslt_keys, int type);
void ngx_http_xsltproc_xslt_keys_list_free(ngx_http_xsltproc_list_t *xslt_keys_list, int type);

/* ngx_http_xsltproc_xslt_keys_cache */
int ngx_http_xsltproc_xslt_keys_cache_init(ngx_log_t *log);
void ngx_http_xsltproc_xslt_keys_cache_destroy(void);
void ngx_http_xsltproc_xslt_keys_cache_put(char *stylesheet_uri, time_t stylesheet_mtime,
    char *document_uri, time_t document_mtime, xsltDocumentPtr xslt_document);
void ngx_http_xsltproc_xslt_keys_cache_get(ngx_http_xsltproc_list_t *xslt_keys_list,
    char *stylesheet_uri, time_t stylesheet_mtime);
void ngx_http_xsltproc_xslt_keys_cache_expire(char *stylesheet_uri, time_t stylesheet_mtime,
    char *document_uri, time_t document_mtime);

#endif /* _NGX_HTTP_XSLTPROC_XSLT_H_INCLUDED_ */
