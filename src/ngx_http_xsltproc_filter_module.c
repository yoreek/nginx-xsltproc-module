
/*
 * Copyright (c) Yuriy Ustyushenko
 * derived from http_xslt_filter (c) Igor Sysoev
 */

#include "ngx_http_xsltproc_filter_module.h"

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_xsltproc_parse_stylesheet(ngx_http_request_t *r,
    u_char *name, ngx_http_xsltproc_xslt_stylesheet_t **xslt_stylesheet)
{
    ngx_http_xsltproc_filter_loc_conf_t   *xlcf;

    xlcf = ngx_http_get_module_loc_conf(r, ngx_http_xsltproc_filter_module);

    *xslt_stylesheet = ngx_http_xsltproc_xslt_stylesheet_parse_file(xlcf, (char *) name);

    if (*xslt_stylesheet == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "xsltParseStylesheetFile(\"%s\") failed",
            name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_parse_params(ngx_http_request_t *r, ngx_array_t *params)
{
    u_char *p, *last, *dst, *src, *value, **s, ch;
    u_int   step;

    if (r->args.len == 0) {
        return NGX_OK;
    }

    if (ngx_array_init(params, r->pool, 4 * 2 + 1, sizeof(char *))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    p       = r->args.data;
    last    = p + r->args.len;
    value   = p;
    step    = 1;

    for ( /* void */ ; p <= last; p++) {
        ch = *p;

        if (step == 1 && (p == last || ch == '=' || ch == '&')) {
            if (p <= value)
                continue;

            s = ngx_array_push(params);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = value;
            *p = '\0';

            if (p != last && ch == '=') {
                p++;
            }

            value = p;

            step = 2;
        }

        if (step == 2 && (p == last || *p == '\0' || *p == '&')) {
            s = ngx_array_push(params);
            if (s == NULL) {
                return NGX_ERROR;
            }

            dst = value;
            src = value;

            if (p > value) {
                ngx_unescape_uri(&dst, &src, p - value, 0);

                *s = value;
            }
            else {
                *s = ngx_http_xsltproc_empty_xpath_expression;
            }

            *dst = '\0';

            value = p + 1;

            step = 1;
        }
    }

    s = ngx_array_push(params);
    if (s == NULL) {
        return NGX_ERROR;
    }

    *s = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_parse_header(ngx_http_request_t *r, ngx_str_t *root, ngx_array_t *sheets)
{
    ngx_uint_t                 i, flags;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *h;
    ngx_str_t                  path;
    u_char                    *last;
    ngx_http_request_t         xslt_r;
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet;
    ngx_http_xsltproc_sheet_t *sheet;

    memcpy(&xslt_r, r, sizeof(xslt_r));

    part = &r->headers_out.headers.part;
    h    = part->elts;

    for (i = 0; i < part->nelts; i++) {
        if (h[i].key.len == sizeof("x-xslt-stylesheet") -1
            && ngx_strncasecmp(h[i].key.data,
                                (u_char *) "x-xslt-stylesheet",
                                sizeof("x-xslt-stylesheet") - 1)
            == 0)
        {
            xslt_r.uri.len   = h[i].value.len;
            xslt_r.uri.data  = ngx_pnalloc(r->pool, xslt_r.uri.len + 1);

            if (xslt_r.uri.data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(xslt_r.uri.data, h[i].value.data, h[i].value.len);

            xslt_r.uri_start = xslt_r.uri.data;
            xslt_r.uri_end   = xslt_r.uri.data + xslt_r.uri.len;

            ngx_str_null(&xslt_r.args);

            if (ngx_http_parse_complex_uri(&xslt_r, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            if (xslt_r.args_start && xslt_r.uri_end > xslt_r.args_start) {
                xslt_r.args.len  = xslt_r.uri_end - xslt_r.args_start;
                xslt_r.args.data = xslt_r.args_start;
            }

            /* path = stylesheet_root + uri */
            path.len  = root->len + xslt_r.uri.len;
            path.data = ngx_pnalloc(r->pool, path.len + 1);
            if (path.data == NULL) {
                return NGX_ERROR;
            }
            last  = ngx_copy(path.data, root->data, root->len);
            last  = ngx_copy(last, xslt_r.uri.data, xslt_r.uri.len);
            *last = '\0';

            if (ngx_http_xsltproc_parse_stylesheet(r, path.data, &xslt_stylesheet)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            sheet = ngx_array_push(sheets);
            if (sheet == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(sheet, sizeof(ngx_http_xsltproc_sheet_t));

            sheet->xslt_stylesheet = xslt_stylesheet;

            if (ngx_http_xsltproc_parse_params(&xslt_r, &sheet->params)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            /* hide header */
            h[i].hash = 0;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_header_filter(ngx_http_request_t *r)
{
    ngx_http_xsltproc_filter_ctx_t       *ctx;
    ngx_http_xsltproc_filter_loc_conf_t  *conf;
    ngx_array_t                          *sheets;
#if (NGX_HTTP_XSLPROC_PROFILER)
    long                                  start = 0, end;
#endif

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xsltproc_filter_module);

#if (NGX_HTTP_XSLPROC_PROFILER)
    if (conf->profiler == 1)
        start = xsltTimestamp();
#endif

    /* next filter if this filter or content type not such as required */
    if (conf->enable != 1 || ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    /* init sheets list */
    sheets = ngx_pcalloc(r->pool, sizeof(ngx_array_t));
    if (sheets == NULL) {
        return NGX_ERROR;
    }
    if (ngx_array_init(sheets, r->pool, 32,
                       sizeof(ngx_http_xsltproc_sheet_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* parse header */
    if (ngx_http_xsltproc_parse_header(r, &conf->stylesheet_root, sheets) != NGX_OK) {
        return NGX_ERROR;
    }

    /* next filter if not spicified any stylesheet */
    if (sheets->nelts == 0) {
        return ngx_http_next_header_filter(r);
    }

    /* get context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_xsltproc_filter_module);

    /* next filter if context already created */
    if (ctx) {
        return ngx_http_next_header_filter(r);
    }

    /* create context */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_xsltproc_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_xsltproc_filter_module);

    ctx->sheets = sheets;

#if (NGX_HTTP_XSLPROC_PROFILER)
    if (conf->profiler == 1) {
        end   = xsltTimestamp();

        ctx->parse_header_start = start;
        ctx->parse_header_time  = end - start;
        ctx->parse_body_start   = end;
    }
#endif

    r->main_filter_need_in_memory = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                              wellFormed;
    ngx_chain_t                     *cl;
    ngx_http_xsltproc_filter_ctx_t  *ctx;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xsltproc_filter_module);

    if (ctx == NULL || ctx->sheets->nelts == 0 || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {

        if (ngx_http_xsltproc_add_chunk(r, ctx, cl->buf) != NGX_OK) {

            if (ctx->ctxt->myDoc) {

#if (NGX_HTTP_XSLTPROC_REUSE_DTD)
                ctx->ctxt->myDoc->extSubset = NULL;
#endif
                xmlFreeDoc(ctx->ctxt->myDoc);
            }

            xmlFreeParserCtxt(ctx->ctxt);

            return ngx_http_xsltproc_send(r, ctx, NULL);
        }

        if (cl->buf->last_buf || cl->buf->last_in_chain) {

            ctx->doc = ctx->ctxt->myDoc;

#if (NGX_HTTP_XSLTPROC_REUSE_DTD)
            ctx->doc->extSubset = NULL;
#endif

            wellFormed = ctx->ctxt->wellFormed;

            xmlFreeParserCtxt(ctx->ctxt);

            if (wellFormed) {
                return ngx_http_xsltproc_send(r, ctx,
                                       ngx_http_xsltproc_apply_stylesheet(r, ctx));
            }

            xmlFreeDoc(ctx->doc);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "not well formed XML document");

            return ngx_http_xsltproc_send(r, ctx, NULL);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_send(ngx_http_request_t *r, ngx_http_xsltproc_filter_ctx_t *ctx,
    ngx_buf_t *b)
{
    ngx_int_t            rc;
    ngx_chain_t          out;
    ngx_pool_cleanup_t  *cln;

    ctx->done = 1;

    if (b == NULL) {
        return ngx_http_filter_finalize_request(r, NULL,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        ngx_free(b->pos);
        return ngx_http_filter_finalize_request(r, NULL,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (r == r->main) {
        r->headers_out.content_length_n = b->last - b->pos;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }

        ngx_http_clear_last_modified(r);
    }

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_free(b->pos);
        return rc;
    }

    cln->handler = ngx_http_xsltproc_cleanup;
    cln->data = b->pos;

    out.buf = b;
    out.next = NULL;

    return ngx_http_next_body_filter(r, &out);
}


static ngx_int_t
ngx_http_xsltproc_add_chunk(ngx_http_request_t *r, ngx_http_xsltproc_filter_ctx_t *ctx,
    ngx_buf_t *b)
{
    int               err;
    xmlParserCtxtPtr  ctxt;

    if (ctx->ctxt == NULL) {

        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
        if (ctxt == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xmlCreatePushParserCtxt() failed");
            return NGX_ERROR;
        }

        ctxt->sax->externalSubset = ngx_http_xsltproc_sax_external_subset;
        ctxt->sax->setDocumentLocator = NULL;
        ctxt->sax->warning = NULL;
        ctxt->sax->error = ngx_http_xsltproc_sax_error;
        ctxt->sax->fatalError = ngx_http_xsltproc_sax_error;
        ctxt->sax->_private = ctx;
        ctxt->replaceEntities = 1;
        ctxt->loadsubset = 1;

        ctx->ctxt = ctxt;
        ctx->request = r;
    }

    err = xmlParseChunk(ctx->ctxt, (char *) b->pos, (int) (b->last - b->pos),
                        (b->last_buf) || (b->last_in_chain));

    if (err == 0) {
        b->pos = b->last;
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "xmlParseChunk() failed, error:%d", err);

    return NGX_ERROR;
}


static void
ngx_http_xsltproc_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = data;

    xmlDocPtr                         doc;
    xmlDtdPtr                         dtd;
    ngx_http_request_t               *r;
    ngx_http_xsltproc_filter_ctx_t       *ctx;
    ngx_http_xsltproc_filter_loc_conf_t  *conf;

    ctx = ctxt->sax->_private;
    r = ctx->request;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xsltproc_filter_module);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter extSubset: \"%s\" \"%s\" \"%s\"",
                   name ? name : (xmlChar *) "",
                   externalId ? externalId : (xmlChar *) "",
                   systemId ? systemId : (xmlChar *) "");

    doc = ctxt->myDoc;

#if (NGX_HTTP_XSLTPROC_REUSE_DTD)

    dtd = conf->dtd;

#else

    dtd = xmlCopyDtd(conf->dtd);
    if (dtd == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xmlCopyDtd() failed");
        return;
    }

    if (doc->children == NULL) {
        xmlAddChild((xmlNodePtr) doc, (xmlNodePtr) dtd);

    } else {
        xmlAddPrevSibling(doc->children, (xmlNodePtr) dtd);
    }

#endif

    doc->extSubset = dtd;
}


static void ngx_cdecl
ngx_http_xsltproc_sax_error(void *data, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = data;

    size_t                       n;
    va_list                      args;
    ngx_http_xsltproc_filter_ctx_t  *ctx;
    u_char                       buf[NGX_MAX_ERROR_STR];

    ctx = ctxt->sax->_private;

    buf[0] = '\0';

    va_start(args, msg);
    n = (size_t) vsnprintf((char *) buf, NGX_MAX_ERROR_STR, msg, args);
    va_end(args);

    while (--n && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                  "libxml2 error: \"%*s\"", n + 1, buf);
}


static ngx_buf_t *
ngx_http_xsltproc_apply_stylesheet(ngx_http_request_t *r,
    ngx_http_xsltproc_filter_ctx_t *ctx)
{
    int                                   len, rc, doc_type;
    ngx_str_t                            *type, *encoding;
    ngx_buf_t                            *b;
    ngx_uint_t                            i;
    xmlChar                              *buf;
    xmlDocPtr                             doc, res;
    const char                          **p;
    ngx_http_xsltproc_sheet_t            *sheet;
    ngx_http_xsltproc_filter_loc_conf_t  *conf;
    ngx_http_xsltproc_xslt_stylesheet_t  *xslt_stylesheet;
#if (NGX_HTTP_XSLPROC_PROFILER)
    xmlDocPtr                             profile_info, summary_profile_info;
    xmlNodePtr                            root, child, child2, child3;
    long                                  start, spent;
    char                                  strbuf[100];
#endif
    conf  = ngx_http_get_module_loc_conf(r, ngx_http_xsltproc_filter_module);
    sheet = ctx->sheets->elts;
    doc   = ctx->doc;

#if (NGX_HTTP_XSLPROC_PROFILER)
    if (conf->profiler == 1 && conf->profiler_stylesheet) {
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

        ctx->parse_body_time = xsltTimestamp() - ctx->parse_body_start;

        summary_profile_info = xmlNewDoc((const xmlChar*) "1.0");
        summary_profile_info->encoding = (const xmlChar*) xmlStrdup((const xmlChar*) "utf-8");

        root = xmlNewDocNode(summary_profile_info, NULL, BAD_CAST "profiler", NULL);
        xmlDocSetRootElement(summary_profile_info, root);

        sprintf(strbuf, "%ld", ctx->parse_header_time);
        xmlSetProp(root, BAD_CAST "parse_header_time", BAD_CAST strbuf);

        sprintf(strbuf, "%ld", ctx->parse_body_time);
        xmlSetProp(root, BAD_CAST "parse_body_time", BAD_CAST strbuf);
    }
#endif

    for (i = 0; i < ctx->sheets->nelts; i++) {
        xslt_stylesheet = sheet[i].xslt_stylesheet;

#if (NGX_HTTP_XSLPROC_PROFILER)
        if (conf->profiler == 1 && conf->profiler_stylesheet) {
            profile_info = NULL;

            start = xsltTimestamp();

            res = ngx_http_xsltproc_xslt_transform(xslt_stylesheet, doc,
                sheet[i].params.elts, conf->profiler, &profile_info);

            spent = xsltTimestamp() - start;

            if (res && profile_info) {
                /* add stylesheet info */
                child = xmlNewChild(root, NULL, BAD_CAST "stylesheet", NULL);
                xmlSetProp(child, BAD_CAST "uri", BAD_CAST xslt_stylesheet->uri);

                sprintf(strbuf, "%ld", spent);
                xmlSetProp(child, BAD_CAST "time", BAD_CAST strbuf);

                /* add profile info */
                xmlAddChild(child, xmlDocCopyNode(xmlDocGetRootElement(profile_info), summary_profile_info, 1));

                /* add document */
                child2 = xmlNewChild(child, NULL, BAD_CAST "document", NULL);
                xmlAddChild(child2, xmlDocCopyNode(xmlDocGetRootElement(doc), summary_profile_info, 1));

                /* add params */
                child2 = xmlNewChild(child, NULL, BAD_CAST "params", NULL);
                if (sheet[i].params.nelts > 0) {
                    p = sheet[i].params.elts;
                    for(; *p != '\0'; p++) {
                        child3 = xmlNewChild(child2, NULL, BAD_CAST "param", NULL);

                        xmlSetProp(child3, BAD_CAST "name", BAD_CAST *p);
                        p++;
                        xmlSetProp(child3, BAD_CAST "value", BAD_CAST *p);
                    }
                }

                xmlFreeDoc(profile_info);
            }
            else {
                xmlFreeDoc(doc);
                if (res) xmlFreeDoc(res);

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "ngx_http_xsltproc_apply_stylesheet: no profile info");
                return NULL;
            }
        }
        else {
            res = ngx_http_xsltproc_xslt_transform(xslt_stylesheet, doc,
                sheet[i].params.elts, conf->profiler, NULL);
        }
#else
        res = ngx_http_xsltproc_xslt_transform(xslt_stylesheet, doc,
            sheet[i].params.elts, 0, NULL);
#endif
        xmlFreeDoc(doc);

        if (res == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xsltApplyStylesheet() failed");
            return NULL;
        }

        doc = res;
    }

#if (NGX_HTTP_XSLPROC_PROFILER)
    if (conf->profiler == 1 && conf->profiler_stylesheet) {
        res = xsltApplyStylesheet(conf->profiler_stylesheet, summary_profile_info, NULL);

        if (res) {
            root = xmlDocCopyNode(xmlDocGetRootElement(res), doc, 1);

            if (root) {
                xmlAddChild(xmlDocGetRootElement(doc)->last, root);
            }
            else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                               "ngx_http_xsltproc_apply_stylesheet: no root in profile info");
            }

            xmlFreeDoc(res);
        }
        else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                           "ngx_http_xsltproc_apply_stylesheet: no profile info");
        }

        xmlFreeDoc(summary_profile_info);
    }
#endif

    /* there must be at least one stylesheet */

    encoding = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (encoding == NULL) {
        return NULL;
    }
    ngx_memzero(encoding, sizeof(ngx_str_t));

    type = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (type == NULL) {
        return NULL;
    }
    ngx_memzero(type, sizeof(ngx_str_t));

    if (r == r->main) {
        type->data = ngx_http_xsltproc_content_type(xslt_stylesheet->stylesheet);
        if (type->data != NULL) {
            type->len  = ngx_strlen(type->data);
            type->data = ngx_pstrdup(r->pool, type);
        }
    }

    encoding->data = ngx_http_xsltproc_encoding(xslt_stylesheet->stylesheet);
    if (encoding->data != NULL) {
        encoding->len  = ngx_strlen(encoding->data);
        encoding->data = ngx_pstrdup(r->pool, encoding);
    }

    doc_type = doc->type;

    rc = xsltSaveResultToString(&buf, &len, doc, xslt_stylesheet->stylesheet);

    xmlFreeDoc(doc);

    if (conf->stylesheet_caching != 1) {
        for (i = 0; i < ctx->sheets->nelts; i++) {
            ngx_http_xsltproc_xslt_stylesheet_free(xslt_stylesheet);
        }
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() failed");
        return NULL;
    }

    if (len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() returned zero-length result");
        return NULL;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_free(buf);
        return NULL;
    }

    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;

    if (encoding->data) {
        r->headers_out.charset.len = encoding->len;
        r->headers_out.charset.data = encoding->data;
    }

    if (r != r->main) {
        return b;
    }

    b->last_buf = 1;

    if (type->data) {
        r->headers_out.content_type_len = type->len;
        r->headers_out.content_type.len = type->len;
        r->headers_out.content_type.data = type->data;

    } else if (doc_type == XML_HTML_DOCUMENT_NODE) {

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&r->headers_out.content_type, "text/html");
    }

    r->headers_out.content_type_lowcase = NULL;

    return b;
}


static u_char *
ngx_http_xsltproc_content_type(xsltStylesheetPtr s)
{
    u_char  *type;

    if (s->mediaType) {
        return s->mediaType;
    }

    for (s = s->imports; s; s = s->next) {

        type = ngx_http_xsltproc_content_type(s);

        if (type) {
            return type;
        }
    }

    return NULL;
}


static u_char *
ngx_http_xsltproc_encoding(xsltStylesheetPtr s)
{
    u_char  *encoding;

    if (s->encoding) {
        return s->encoding;
    }

    for (s = s->imports; s; s = s->next) {

        encoding = ngx_http_xsltproc_encoding(s);

        if (encoding) {
            return encoding;
        }
    }

    return NULL;
}


static void
ngx_http_xsltproc_cleanup(void *data)
{
    ngx_free(data);
}


static char *
ngx_http_xsltproc_entities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xsltproc_filter_loc_conf_t *xlcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_pool_cleanup_t                *cln;
    ngx_http_xsltproc_file_t              *file;
    ngx_http_xsltproc_filter_main_conf_t  *xmcf;

    if (xlcf->dtd) {
        return "is duplicate";
    }

    value = cf->args->elts;

    xmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xsltproc_filter_module);

    file = xmcf->dtd_files.elts;
    for (i = 0; i < xmcf->dtd_files.nelts; i++) {
        if (ngx_strcmp(file[i].name, &value[1].data) == 0) {
            xlcf->dtd = file[i].data;
            return NGX_CONF_OK;
        }
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    xlcf->dtd = xmlParseDTD(NULL, (xmlChar *) value[1].data);

    if (xlcf->dtd == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "xmlParseDTD() failed");
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_xsltproc_cleanup_dtd;
    cln->data = xlcf->dtd;

    file = ngx_array_push(&xmcf->dtd_files);
    if (file == NULL) {
        return NGX_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = xlcf->dtd;

    return NGX_CONF_OK;
}


static void
ngx_http_xsltproc_cleanup_dtd(void *data)
{
    xmlFreeDtd(data);
}


#if (NGX_HTTP_XSLPROC_PROFILER)
static char *
ngx_http_xsltproc_profiler_stylesheet(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xsltproc_filter_loc_conf_t *xlcf = conf;

    ngx_str_t                             *value;
    ngx_pool_cleanup_t                    *cln;
    ngx_http_xsltproc_filter_main_conf_t  *xmcf;

    if (xlcf->profiler_stylesheet) {
        return "is duplicate";
    }

    value = cf->args->elts;

    xmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xsltproc_filter_module);

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    xlcf->profiler_stylesheet = xsltParseStylesheetFile((xmlChar *) value[1].data);

    if (xlcf->profiler_stylesheet == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "xsltParseStylesheetFile() failed");
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_xsltproc_cleanup_profiler_stylesheet;
    cln->data = xlcf->profiler_stylesheet;

    return NGX_CONF_OK;
}


static void
ngx_http_xsltproc_cleanup_profiler_stylesheet(void *data)
{
    xsltFreeStylesheet(data);
}
#endif

static void *
ngx_http_xsltproc_filter_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_xsltproc_filter_main_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_xsltproc_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->pool = cf->pool;

    if (ngx_array_init(&conf->dtd_files, cf->pool, 32,
                       sizeof(ngx_http_xsltproc_file_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&conf->sheet_cache, cf->pool, 32,
                       sizeof(ngx_http_xsltproc_file_t))
        != NGX_OK)
    {
        return NULL;
    }

    xmlInitParser();
    exsltRegisterAll();

    return conf;
}


static void *
ngx_http_xsltproc_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_xsltproc_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_xsltproc_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->dtd = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->stylesheet_root.len = { 0, NULL };
     */

    conf->enable                     = NGX_CONF_UNSET;
    conf->stylesheet_caching         = NGX_CONF_UNSET;
    conf->stylesheet_check_if_modify = NGX_CONF_UNSET;
    conf->document_caching           = NGX_CONF_UNSET;
    conf->keys_caching               = NGX_CONF_UNSET;
#if (NGX_HTTP_XSLPROC_PROFILER)
    conf->profiler                   = NGX_CONF_UNSET;
#endif

    return conf;
}


static char *
ngx_http_xsltproc_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xsltproc_filter_loc_conf_t *prev = parent;
    ngx_http_xsltproc_filter_loc_conf_t *conf = child;

    if (conf->dtd == NULL) {
        conf->dtd = prev->dtd;
    }

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_xsltproc_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->enable,
        prev->enable, 0);

    ngx_conf_merge_value(conf->stylesheet_caching,
        prev->stylesheet_caching, 0);

    ngx_conf_merge_value(conf->stylesheet_check_if_modify,
        prev->stylesheet_check_if_modify, 0);

    ngx_conf_merge_str_value(conf->stylesheet_root,
        prev->stylesheet_root, "");

#if (NGX_HTTP_XSLPROC_PROFILER)
    ngx_conf_merge_value(conf->profiler,
        prev->profiler, 0);

    if (conf->profiler_stylesheet == NULL)
        conf->profiler_stylesheet = prev->profiler_stylesheet;
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_xsltproc_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_xsltproc_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_xsltproc_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_filter_init_process(ngx_cycle_t *cycle)
{
    ngx_http_xsltproc_xslt_init(cycle->log);

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, cycle->log, 0, "xsltproc filter init");
#endif

    return NGX_OK;
}


static void
ngx_http_xsltproc_filter_exit(ngx_cycle_t *cycle)
{
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, cycle->log, 0, "xsltproc filter exit");
#endif

    ngx_http_xsltproc_xslt_cleanup();

    xmlCleanupParser();
}
