#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

/*static xsltTransformContextPtr tr_ctxt = NULL;*/
static ngx_log_t *xslt_log = NULL;

#if (NGX_HTTP_XSLTPROC_PROFILER)
/*
 * <profiler parse_header_time="20" parse_body_time="44">
 *   <stylesheet uri="main.xsl" time="444">
 *     <profile>
 *       <template name="" match="*" mode="" ... />
 *       ...
 *     </profile>
 *     <document>
 *       <root>
 *         ...
 *       </root>
 *     </document>
 *     <params>
 *       <param name="name1" value="'value1'" />
 *       ...
 *     </params>
 *   </stylesheet>
 *   ...
 * </profiler>
 */

void ngx_http_xsltproc_xslt_profiler_init(ngx_http_xsltproc_profiler_t *profiler) {

    xmlNodePtr root;
    char       strbuf[100];

    profiler->parse_body_time = xsltTimestamp() - profiler->parse_body_start;

    profiler->summary_profile_info = xmlNewDoc((const xmlChar*) "1.0");
    profiler->summary_profile_info->encoding = (const xmlChar*) xmlStrdup((const xmlChar*) "utf-8");

    root = xmlNewDocNode(profiler->summary_profile_info, NULL, BAD_CAST "profiler", NULL);
    xmlDocSetRootElement(profiler->summary_profile_info, root);

    sprintf(strbuf, "%ld", profiler->parse_header_time);
    xmlSetProp(root, BAD_CAST "parse_header_time", BAD_CAST strbuf);

    sprintf(strbuf, "%ld", profiler->parse_body_time);
    xmlSetProp(root, BAD_CAST "parse_body_time", BAD_CAST strbuf);

    sprintf(strbuf, "%d", profiler->repeat);
    xmlSetProp(root, BAD_CAST "repeat", BAD_CAST strbuf);
}

void ngx_http_xsltproc_xslt_profiler_done(ngx_http_xsltproc_profiler_t *profiler,
                                          xsltStylesheetPtr stylesheet, xmlDocPtr doc) {

    xmlNodePtr root;
    xmlDocPtr  res;

    res = xsltApplyStylesheet(stylesheet, profiler->summary_profile_info, NULL);

    if (res) {
        root = xmlDocCopyNode(xmlDocGetRootElement(res), doc, 1);

        if (root) {
            xmlAddChild(xmlDocGetRootElement(doc)->last, root);
        }
        else {
            ngx_log_error(NGX_LOG_ERR, xslt_log, 0,
                           "ngx_http_xsltproc_xslt_profiler_done: no root in profile info");
        }

        xmlFreeDoc(res);
    }
    else {
        ngx_log_error(NGX_LOG_ERR, xslt_log, 0,
                       "ngx_http_xsltproc_xslt_profiler_done: no profile info");
    }

    xmlFreeDoc(profiler->summary_profile_info);
}

static void ngx_http_xsltproc_xslt_profiler_add_info(ngx_http_xsltproc_profiler_t *profiler,
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet, const char **params,
    long spent, xmlDocPtr doc, xmlDocPtr profile_info) {

    xmlNodePtr root, child, child2, child3;
    char       strbuf[100];

    root = xmlDocGetRootElement(profiler->summary_profile_info);

    /* add stylesheet info */
    child = xmlNewChild(root, NULL, BAD_CAST "stylesheet", NULL);
    xmlSetProp(child, BAD_CAST "uri", BAD_CAST xslt_stylesheet->uri);

    sprintf(strbuf, "%ld", spent);
    xmlSetProp(child, BAD_CAST "time", BAD_CAST strbuf);

    /* add profile info */
    xmlAddChild(child, xmlDocCopyNode(xmlDocGetRootElement(profile_info), profiler->summary_profile_info, 1));

    /* add document */
    child2 = xmlNewChild(child, NULL, BAD_CAST "document", NULL);
    xmlAddChild(child2, xmlDocCopyNode(xmlDocGetRootElement(doc), profiler->summary_profile_info, 1));

    /* add params */
    child2 = xmlNewChild(child, NULL, BAD_CAST "params", NULL);
    if (params != NULL) {
        for(; *params != '\0'; params++) {
            child3 = xmlNewChild(child2, NULL, BAD_CAST "param", NULL);

            xmlSetProp(child3, BAD_CAST "name", BAD_CAST *params);
            params++;
            xmlSetProp(child3, BAD_CAST "value", BAD_CAST *params);
        }
    }
}
#endif

#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLTPROC_XSLT_KEYS_CACHING)
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

#if (NGX_HTTP_XSLTPROC_PROFILER)
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
#endif

#if (NGX_HTTP_XSLTPROC_PROFILER)
xmlDocPtr ngx_http_xsltproc_xslt_transform(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet,
    xmlDocPtr doc, const char **params, int profiler_enabled, ngx_http_xsltproc_profiler_t *profiler)
{
    xmlDocPtr               result = NULL;
    xsltTransformContextPtr ctxt;
    xmlDocPtr               profile_info;
    long                    start = 0, spent = 0;
    int                     i = 1, repeat = 1;

    if (profiler_enabled == 1 && profiler != NULL) {
        repeat = profiler->repeat;
    }

    for (i = 1; i <= repeat; i++) {
        ctxt = (xsltTransformContextPtr) xsltNewTransformContext(xslt_stylesheet->stylesheet, doc);

#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLTPROC_XSLT_KEYS_CACHING)
        ngx_http_xsltproc_xslt_restore_keys(xslt_stylesheet, &ctxt->docList);
#endif

        if (profiler_enabled == 1) {
            /* reset internal template counters */
            if (i == 1) {
                ngx_http_xsltproc_xslt_reset_profile_info(ctxt);
                start = xsltTimestamp();
            }

            result = (xmlDocPtr) xsltApplyStylesheetUser(xslt_stylesheet->stylesheet, doc, params, NULL, stderr, ctxt);

            if (result == NULL)
                break;

            spent = xsltTimestamp() - start;

            if (profiler != NULL && i == repeat) {
                profile_info = xsltGetProfileInformation(ctxt);
                if (profile_info != NULL) {
                    ngx_http_xsltproc_xslt_profiler_add_info(profiler, xslt_stylesheet,
                                                             params, spent, doc, profile_info);
                    xmlFreeDoc(profile_info);
                }
                else {
                    xmlFreeDoc(result);
                    result = NULL;

                    ngx_log_error(NGX_LOG_ERR, xslt_log, 0,
                                  "ngx_http_xsltproc_xslt_transform: no profile info");
                }
            }
        }
        else {
            result = (xmlDocPtr) xsltApplyStylesheetUser(xslt_stylesheet->stylesheet, doc, params, NULL, NULL, ctxt);
        }

#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLTPROC_XSLT_KEYS_CACHING)
        ngx_http_xsltproc_xslt_backup_keys(xslt_stylesheet, &ctxt->docList);
#endif

        xsltFreeTransformContext(ctxt);

        if (i < repeat && result != NULL) {
            xmlFreeDoc(result);
            result = NULL;
        }
    }

    return result;
}
#else
xmlDocPtr ngx_http_xsltproc_xslt_transform(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet,
    xmlDocPtr doc, const char **params)
{
    xmlDocPtr               result;
    xsltTransformContextPtr ctxt;

    ctxt = (xsltTransformContextPtr) xsltNewTransformContext(xslt_stylesheet->stylesheet, doc);

#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLTPROC_XSLT_KEYS_CACHING)
    ngx_http_xsltproc_xslt_restore_keys(xslt_stylesheet, &ctxt->docList);
#endif

    result = (xmlDocPtr) xsltApplyStylesheetUser(xslt_stylesheet->stylesheet, doc, params, NULL, NULL, ctxt);

#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLTPROC_XSLT_KEYS_CACHING)
    ngx_http_xsltproc_xslt_backup_keys(xslt_stylesheet, &ctxt->docList);
#endif

    xsltFreeTransformContext(ctxt);

    return result;
}
#endif

void ngx_http_xsltproc_xslt_init(ngx_log_t *log) {
    xslt_log = log;

    /*xsltSetGenericDebugFunc(stderr, NULL);*/
    exsltRegisterAll();
    /*xsltRegisterTestModule();*/
    /*xsltDebugDumpExtensions(NULL);*/

    ngx_http_xsltproc_xslt_function_init(log);
    ngx_http_xsltproc_xslt_stylesheet_init(log);

#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING)
    ngx_http_xsltproc_xslt_document_init(log);
    ngx_http_xsltproc_xslt_keys_init(log);
#endif

}

void ngx_http_xsltproc_xslt_cleanup(void) {
#if (NGX_HTTP_XSLTPROC_XSLT_DOCUMENT_CACHING)
    ngx_http_xsltproc_xslt_keys_destroy();
    ngx_http_xsltproc_xslt_document_destroy();
#endif

    ngx_http_xsltproc_xslt_stylesheet_destroy();

    xsltCleanupGlobals();
}
