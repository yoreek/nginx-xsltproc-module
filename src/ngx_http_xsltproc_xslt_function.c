#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static ngx_log_t *xslt_function_log = NULL;

static void
ngx_http_xsltproc_xslt_function_join(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlChar *ret = NULL, *sep = NULL, *str = NULL;
    xmlNodeSetPtr nodeSet = NULL;
    int i, j;

    if (nargs  < 2) {
        xmlXPathSetArityError(ctxt);
        return;
    }

    if (xmlXPathStackIsNodeSet(ctxt)) {
        xmlXPathSetTypeError(ctxt);
        return;
    }

    sep = xmlXPathPopString(ctxt);

    for (i = 1; i < nargs; i++) {
        if (!xmlXPathStackIsNodeSet(ctxt)) {
            str = xmlXPathPopString(ctxt);

            if (i == 1) {
                ret = xmlStrdup(str);
            }
            else {
                ret = xmlStrcat(ret, sep);
                ret = xmlStrcat(ret, str);
            }

            xmlFree(str);
        }
        else {
            nodeSet = xmlXPathPopNodeSet(ctxt);
            if (xmlXPathCheckError(ctxt)) {
                xmlXPathSetTypeError(ctxt);
                goto fail;
            }

            for (j = 0; j < nodeSet->nodeNr; j++) {
                str = xmlXPathCastNodeToString(nodeSet->nodeTab[j]);

                if (i == 1 && j == 1) {
                    ret = xmlStrdup(str);
                }
                else {
                    ret = xmlStrcat(ret, sep);
                    ret = xmlStrcat(ret, str);
                }

                xmlFree(str);
            }

            xmlXPathFreeNodeSet(nodeSet);
        }
    }

    xmlXPathReturnString(ctxt, ret);

fail:
    if (sep != NULL)
        xmlFree(sep);
}

static void
ngx_http_xsltproc_xslt_function_case_convert(xmlXPathParserContextPtr ctxt,
    int nargs, ngx_http_xsltproc_xslt_case_convert_func_t case_convert) {

    xmlChar *src = NULL, *dst = NULL;

    UChar32 c;
    int32_t i, j, len, buf_len;
    UBool isError;
    UConverter *conv;
    UErrorCode status;
    UChar *buffer1, *buffer2;

    if (nargs != 1) {
        xmlXPathSetArityError(ctxt);
        return;
    }

    status = U_ZERO_ERROR;
    conv = ucnv_open("UTF8", &status);
    if (U_FAILURE(status)) {
        xsltTransformError(xsltXPathGetTransformContext(ctxt),
                           NULL, NULL, "xsltICUSortFunction: Error opening converter\n");
    }

    src = xmlXPathPopString(ctxt);

    len     = xmlUTF8Strlen(src);

    buf_len = len * sizeof(UChar) * 2;
    buffer1 = xmlMalloc(buf_len);
    buffer2 = xmlMalloc(buf_len);
    dst     = xmlMalloc(buf_len);

    memset(dst, 0, buf_len);

    ucnv_toUChars(conv, buffer1, buf_len, (const char *) src, -1, &status);

    isError = 0;
    for(i = j = 0; j < len && !isError; /* U16_NEXT post-increments */) {
        U16_NEXT(buffer1, i, len, c);
        c = case_convert(c);
        U16_APPEND(buffer2, j, len, c, isError);
    }

    ucnv_fromUChars(conv, (char *) dst, buf_len, buffer2, len, &status);

    ucnv_close(conv);
    xmlFree(buffer1);
    xmlFree(buffer2);

    xmlXPathReturnString(ctxt, dst);

    if (src != NULL)
        xmlFree(src);
}

static void
ngx_http_xsltproc_xslt_function_uc(xmlXPathParserContextPtr ctxt, int nargs) {
    ngx_http_xsltproc_xslt_function_case_convert(ctxt, nargs, u_toupper);
}

static void
ngx_http_xsltproc_xslt_function_lc(xmlXPathParserContextPtr ctxt, int nargs) {
    ngx_http_xsltproc_xslt_function_case_convert(ctxt, nargs, u_tolower);
}

static void
ngx_http_xsltproc_xslt_function_ltrim(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlChar *src = NULL, *tmp = NULL, *dst = NULL;
    int len;

    if (nargs != 1) {
        xmlXPathSetArityError(ctxt);
        return;
    }

    src = xmlXPathPopString(ctxt);

    if (*src == '\0' || *src != ' ') {
        dst = src;
        src = NULL;
    }
    else {
        len = strlen((char *) src);
        tmp = src;
        while (*tmp != '\0' && *tmp == ' ') {
            tmp++;
            len--;
        }
        dst = xmlMalloc(len + 1);
        memcpy(dst, tmp, len + 1);
    }

    xmlXPathReturnString(ctxt, dst);

    if (src != NULL)
        xmlFree(src);
}

static void
ngx_http_xsltproc_xslt_function_rtrim(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlChar *src = NULL, *tmp = NULL, *last = NULL;

    if (nargs != 1) {
        xmlXPathSetArityError(ctxt);
        return;
    }

    src = xmlXPathPopString(ctxt);

    tmp = src;

    while (*tmp != '\0') {
        if (*tmp != ' ') last = tmp;
        tmp++;
    }

    if (last == NULL)
        *src = '\0';
    else
        *++last = '\0';

    xmlXPathReturnString(ctxt, src);
}

static void
ngx_http_xsltproc_xslt_function_trim(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlChar *src = NULL, *tmp = NULL, *first = NULL, *last = NULL;
    int len;

    if (nargs != 1) {
        xmlXPathSetArityError(ctxt);
        return;
    }

    src = xmlXPathPopString(ctxt);

    tmp = src;

    while (*tmp != '\0') {
        if (*tmp != ' ') {
            last = tmp;
            if (first == NULL) first = tmp;
        }
        tmp++;
    }

    if (last == NULL) {
        *src = '\0';
    }
    else if (first == src) {
        *++last = '\0';
    }
    else {
        len = last - first + 1;
        tmp = xmlMalloc(len + 1);

        memcpy(tmp, first, len);

        tmp[len] = '\0';

        xmlFree(src);

        src = tmp;
    }

    xmlXPathReturnString(ctxt, src);
}

static void *
ngx_http_xsltproc_xslt_function_ext_init(xsltTransformContextPtr ctxt, const xmlChar * URI) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_function_log, 0,
                       "ngx_http_xsltproc_xslt_function_ext_init: Registered plugin module : %s",
                       URI);
#endif

    return NULL;
}

static void
ngx_http_xsltproc_xslt_function_ext_shutdown(xsltTransformContextPtr ctxt,
                    const xmlChar * URI, void *data) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_function_log, 0,
                       "ngx_http_xsltproc_xslt_function_ext_shutdown: Unregistered plugin module : %s",
                       URI);
#endif
}

static void *
ngx_http_xsltproc_xslt_function_ext_style_init(xsltStylesheetPtr style ATTRIBUTE_UNUSED,
                     const xmlChar * URI) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_function_log, 0,
                       "ngx_http_xsltproc_xslt_function_ext_style_init: Registered plugin module : %s",
                       URI);
#endif

    return NULL;
}

static void
ngx_http_xsltproc_xslt_function_ext_style_shutdown(xsltStylesheetPtr style ATTRIBUTE_UNUSED,
                         const xmlChar * URI, void *data)
{
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_function_log, 0,
                       "ngx_http_xsltproc_xslt_function_ext_style_shutdown: Unregistered plugin module : %s",
                       URI);
#endif
}

int
ngx_http_xsltproc_xslt_function_init(ngx_log_t *log) {
    xslt_function_log = log;

    xsltInitGlobals();

    xsltRegisterExtModuleFull((const xmlChar *) XSLT_FUNCTION_URL,
                              ngx_http_xsltproc_xslt_function_ext_init,
                              ngx_http_xsltproc_xslt_function_ext_shutdown,
                              ngx_http_xsltproc_xslt_function_ext_style_init,
                              ngx_http_xsltproc_xslt_function_ext_style_shutdown);

    xsltRegisterExtModuleFunction((const xmlChar *) "uc",
                                  (const xmlChar *) XSLT_FUNCTION_URL,
                                  ngx_http_xsltproc_xslt_function_uc);
    xsltRegisterExtModuleFunction((const xmlChar *) "lc",
                                  (const xmlChar *) XSLT_FUNCTION_URL,
                                  ngx_http_xsltproc_xslt_function_lc);
    xsltRegisterExtModuleFunction((const xmlChar *) "join",
                                  (const xmlChar *) XSLT_FUNCTION_URL,
                                  ngx_http_xsltproc_xslt_function_join);
    xsltRegisterExtModuleFunction((const xmlChar *) "ltrim",
                                  (const xmlChar *) XSLT_FUNCTION_URL,
                                  ngx_http_xsltproc_xslt_function_ltrim);
    xsltRegisterExtModuleFunction((const xmlChar *) "rtrim",
                                  (const xmlChar *) XSLT_FUNCTION_URL,
                                  ngx_http_xsltproc_xslt_function_rtrim);
    xsltRegisterExtModuleFunction((const xmlChar *) "trim",
                                  (const xmlChar *) XSLT_FUNCTION_URL,
                                  ngx_http_xsltproc_xslt_function_trim);
    return 1;
}
