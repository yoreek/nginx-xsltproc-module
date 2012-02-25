#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

/*static xsltTransformContextPtr tr_ctxt = NULL;*/
static ngx_log_t *xslt_log = NULL;

#ifdef NGX_DEBUG
static void print_imports(xsltStylesheetPtr style) {
    while (style != NULL) {
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_log, 0,
                       "print_imports2: import stylesheet: %s",
                       style->doc->URL);

        if (style->imports != NULL) {
            style = style->imports;
        } else if (style->next != NULL) {
            style = style->next;
        } else {
            while ((style = style->parent) != NULL) {
                if (style->next != NULL) {
                    style = style->next;
                    break;
                }
            }
        }
    }
}
#endif

#if (NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING)
static void ngx_http_xsltproc_xslt_backup_keys(
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet, xsltDocumentPtr *doc_list)
{
    ngx_http_xsltproc_xml_document_extra_info_t *doc_extra_info;
    xmlDocPtr                                    doc;
    xsltDocumentPtr                              xslt_document;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_log, 0,
                   "ngx_http_xsltproc_xslt_backup_keys: stylesheet %s",
                   xslt_stylesheet->uri);
#endif

    for ( ;; ) {
        xslt_document = *doc_list;

        if (xslt_document == NULL || xslt_document->main)
            break;

        doc            = xslt_document->doc;
        doc_extra_info = doc->_private;

#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_log, 0,
                   "ngx_http_xsltproc_xslt_backup_keys: document %s",
                   doc->URL);
#endif

        ngx_http_xsltproc_xslt_keys_cache_put(xslt_stylesheet->uri, xslt_stylesheet->mtime,
            (char *) doc->URL, doc_extra_info->mtime, xslt_document);

        *doc_list = xslt_document->next;
    }
}

static void ngx_http_xsltproc_xslt_restore_keys(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet,
    xsltDocumentPtr *doc_list)
{
    ngx_http_xsltproc_list_t      *el, xslt_keys_list;
    ngx_http_xsltproc_xslt_keys_t *xslt_keys;
    xsltDocumentPtr xslt_document;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_log, 0,
                   "ngx_http_xsltproc_xslt_restore_keys: stylesheet %s",
                   xslt_stylesheet->uri);
#endif

    ngx_http_xsltproc_xslt_keys_cache_get(&xslt_keys_list, xslt_stylesheet->uri, xslt_stylesheet->mtime);

    for (
        el  = ngx_http_xsltproc_list_first(&xslt_keys_list);
        el != ngx_http_xsltproc_list_end(&xslt_keys_list);
        el  = ngx_http_xsltproc_list_next(el)
    ) {
        xslt_keys = (ngx_http_xsltproc_xslt_keys_t *) el;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_log, 0,
                   "ngx_http_xsltproc_xslt_restore_keys: document %s",
                   xslt_keys->document_uri);
#endif

        if ((xslt_document = ngx_http_xsltproc_malloc(sizeof(xsltDocument))) == NULL) {
            return;
        }
        memcpy(xslt_document, xslt_keys->xslt_document, sizeof(xsltDocument));

        xslt_document->next = *doc_list;
        *doc_list           = xslt_document;
    }

    ngx_http_xsltproc_xslt_keys_list_free(&xslt_keys_list, XSLT_KEYS_LIST_FREE_NONE);
}
#endif

static void ngx_http_xsltproc_xslt_reset_profile_info(xsltTransformContextPtr ctxt) {
    xsltTemplatePtr   template;
    xsltStylesheetPtr style;

    style = ctxt->style;

    while (style != NULL) {
        template = style->templates;

        while (template != NULL) {
            template->nbCalls = 0;
            template->time    = 0;

            template = template->next;
        }

        style = xsltNextImport(style);
    }
}

xmlDocPtr ngx_http_xsltproc_xslt_transform(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet,
    xmlDocPtr doc, const char **params, xmlDocPtr *profile_info)
{
    xmlDocPtr result;
    xsltTransformContextPtr ctxt;

    ctxt = (xsltTransformContextPtr) xsltNewTransformContext(xslt_stylesheet->stylesheet, doc);

#if (NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING)
    ngx_http_xsltproc_xslt_restore_keys(xslt_stylesheet, &ctxt->docList);
#endif

    if (profile_info) {
        /* reset internal template counters */
        ngx_http_xsltproc_xslt_reset_profile_info(ctxt);

        result = (xmlDocPtr) xsltApplyStylesheetUser(xslt_stylesheet->stylesheet, doc, params, NULL, stderr, ctxt);

        if (result)
            *profile_info = xsltGetProfileInformation(ctxt);
    }
    else {
        result = (xmlDocPtr) xsltApplyStylesheetUser(xslt_stylesheet->stylesheet, doc, params, NULL, NULL, ctxt);
    }

#ifdef NGX_DEBUG
    print_imports(xslt_stylesheet->stylesheet);
#endif

#if (NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING)
    ngx_http_xsltproc_xslt_backup_keys(xslt_stylesheet, &ctxt->docList);
#endif

    xsltFreeTransformContext(ctxt);

    return result;
}

void ngx_http_xsltproc_xslt_init(ngx_log_t *log) {
    xslt_log = log;

    /*xsltSetGenericDebugFunc(stderr, NULL);*/
    exsltRegisterAll();
    /*xsltRegisterTestModule();*/
    /*xsltDebugDumpExtensions(NULL);*/

    ngx_http_xsltproc_xslt_stylesheet_init(log);

#if (NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING)
    ngx_http_xsltproc_xslt_document_init(log);
    ngx_http_xsltproc_xslt_keys_init(log);
#endif

}

void ngx_http_xsltproc_xslt_cleanup(void) {
#if (NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING)
    ngx_http_xsltproc_xslt_keys_destroy();
    ngx_http_xsltproc_xslt_document_destroy();
#endif

    ngx_http_xsltproc_xslt_stylesheet_destroy();

    xsltCleanupGlobals();
}
