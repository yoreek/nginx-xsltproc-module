#ifndef _NGX_HTTP_XSLTPROC_CORE_H_INCLUDED_
#define _NGX_HTTP_XSLTPROC_CORE_H_INCLUDED_

#include <sys/un.h>
#include <sys/stat.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/xmlsave.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/documents.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#include <libxslt/keys.h>
#include <libexslt/exslt.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

void *ngx_http_xsltproc_malloc(size_t size);
void ngx_http_xsltproc_free(void *p);
time_t ngx_http_xsltproc_last_modify(const char *file_name);

#include "ngx_http_xsltproc_list.h"

typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           stylesheet_caching;
    ngx_flag_t           stylesheet_check_if_modify;
    ngx_flag_t           document_caching;
    ngx_flag_t           keys_caching;

    xmlDtdPtr            dtd;
    ngx_hash_t           types;
    ngx_array_t         *types_keys;
} ngx_http_xsltproc_filter_loc_conf_t;

#endif /* _NGX_HTTP_XSLTPROC_CORE_H_INCLUDED_ */
