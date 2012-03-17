#ifndef _NGX_HTTP_XSLTPROC_CORE_H_INCLUDED_
#define _NGX_HTTP_XSLTPROC_CORE_H_INCLUDED_

#include <sys/un.h>
#include <sys/stat.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/xmlsave.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/documents.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#include <libxslt/imports.h>
#include <libxslt/keys.h>
#include <libxslt/extensions.h>
#include <libexslt/exslt.h>

#include <unicode/ucnv.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>
#include <unicode/uloc.h>
#include <unicode/ucol.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

void *ngx_http_xsltproc_malloc(size_t size);
void ngx_http_xsltproc_free(void *p);
time_t ngx_http_xsltproc_last_modify(const char *file_name);

#include "ngx_http_xsltproc_list.h"

#ifndef NGX_HTTP_XSLPROC_PROFILER
#define NGX_HTTP_XSLPROC_PROFILER  1
#endif

#ifndef NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING
#define NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING  1
#endif

#ifndef NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING
#define NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING  1
#endif

typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           stylesheet_caching;
    ngx_flag_t           stylesheet_check_if_modify;
    ngx_str_t            stylesheet_root;
    ngx_flag_t           document_caching;
    ngx_flag_t           keys_caching;
#if (NGX_HTTP_XSLPROC_PROFILER)
    ngx_flag_t           profiler;
    xsltStylesheetPtr    profiler_stylesheet;
#endif
    xmlDtdPtr            dtd;
    ngx_hash_t           types;
    ngx_array_t         *types_keys;
} ngx_http_xsltproc_filter_loc_conf_t;

#endif /* _NGX_HTTP_XSLTPROC_CORE_H_INCLUDED_ */
