
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


#if (NGX_HTTP_XSLTPROC_MEMCACHED)
static ngx_int_t
ngx_http_xsltproc_parse_header(ngx_http_request_t *r, ngx_str_t *root,
                               ngx_array_t *sheets, ngx_str_t *memcached_key)
#else
static ngx_int_t
ngx_http_xsltproc_parse_header(ngx_http_request_t *r, ngx_str_t *root,
                               ngx_array_t *sheets)
#endif
{
    ngx_uint_t                           i;
    ngx_list_part_t                     *part;
    ngx_table_elt_t                     *h;
    ngx_str_t                            path;
    u_char                              *last;
    ngx_http_request_t                   xslt_r;
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet;
    ngx_http_xsltproc_sheet_t           *sheet;

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
#if (NGX_HTTP_XSLTPROC_MEMCACHED)
        else if (h[i].key.len == sizeof("x-xslt-memcached-key") -1
            && ngx_strncasecmp(h[i].key.data,
                                (u_char *) "x-xslt-memcached-key",
                                sizeof("x-xslt-memcached-key") - 1)
            == 0)
        {
            memcached_key->len  = h[i].value.len;
            memcached_key->data = ngx_pnalloc(r->pool, h[i].value.len);

            if (memcached_key->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(memcached_key->data, h[i].value.data, h[i].value.len);

            /* hide header */
            h[i].hash = 0;
        }
#endif
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xsltproc_header_filter(ngx_http_request_t *r)
{
    ngx_http_xsltproc_filter_ctx_t       *ctx;
    ngx_http_xsltproc_filter_loc_conf_t  *conf;
    ngx_array_t                          *sheets;
#if (NGX_HTTP_XSLTPROC_MEMCACHED)
    ngx_str_t                             memcached_key;
#endif
#if (NGX_HTTP_XSLTPROC_PROFILER)
    long                                  start = 0, end;
#endif

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xsltproc_filter_module);

#if (NGX_HTTP_XSLTPROC_PROFILER)
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
#if (NGX_HTTP_XSLTPROC_MEMCACHED)
    memcached_key.data = NULL;
    memcached_key.len = 0;

    if (ngx_http_xsltproc_parse_header(r, &conf->stylesheet_root, sheets, &memcached_key) != NGX_OK) {
#else
    if (ngx_http_xsltproc_parse_header(r, &conf->stylesheet_root, sheets) != NGX_OK) {
#endif
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

#if (NGX_HTTP_XSLTPROC_MEMCACHED)
    if (conf->memcached_enable == 1
        && conf->memcached != NULL
        && (memcached_key.len > 0 || conf->memcached_key_auto == 1)
    ) {
        ctx->memcached                 = conf->memcached;

        ctx->memcached_key.len         = memcached_key.len;
        ctx->memcached_key.data        = memcached_key.data;

        ctx->memcached_key_prefix.len  = conf->memcached_key_prefix.len;
        ctx->memcached_key_prefix.data = conf->memcached_key_prefix.data;

        ctx->memcached_expire          = conf->memcached_expire;
    }
#endif

#if (NGX_HTTP_XSLTPROC_PROFILER)
    if (conf->profiler == 1) {
        ctx->profiler = ngx_pcalloc(r->pool, sizeof(ngx_http_xsltproc_profiler_t));
        if (ctx->profiler == NULL) {
            return NGX_ERROR;
        }

        end   = xsltTimestamp();

        ctx->profiler->parse_header_start = start;
        ctx->profiler->parse_header_time  = end - start;
        ctx->profiler->parse_body_start   = end;

        if (conf->profiler_repeat == 1) {
            ctx->profiler->repeat = 20;
        }
        else {
            ctx->profiler->repeat = 1;
        }
    }
#endif

    r->main_filter_need_in_memory = 1;

    return NGX_OK;
}

#if (NGX_HTTP_XSLTPROC_MEMCACHED)
static ngx_buf_t *
ngx_http_xsltproc_memcached_get(ngx_http_request_t *r, ngx_chain_t *in,
                                ngx_http_xsltproc_filter_ctx_t *ctx)
{
    ngx_chain_t                         *cl;
    ngx_uint_t                           i, j;
    int                                  doc_type = 0;
    xmlChar                             *value;
    size_t                               value_length;
    uint32_t                             flags;
    memcached_return_t                   memcached_return;
    ngx_buf_t                           *b;
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet;
    ngx_http_xsltproc_sheet_t           *sheet;
    ngx_md5_t                            md5;
    u_char                               md5_buf[16];
    char                               **params;

    sheet = ctx->sheets->elts;

    ctx->memcached_done = 1;

    ctx->memcached_key_real.data = ctx->memcached_key.data;
    ctx->memcached_key_real.len  = ctx->memcached_key.len;

    if (ctx->memcached_key_prefix.len > 0 || ctx->memcached_key.len == 0) {
        ctx->memcached_key_real.len = ctx->memcached_key.len + ctx->memcached_key_prefix.len;
        if (ctx->memcached_key.len == 0)
            ctx->memcached_key_real.len += 32;

        ctx->memcached_key_real.data = ngx_pcalloc(r->pool, ctx->memcached_key_real.len);
        if (ctx->memcached_key_real.data == NULL)
            return NULL;

        if (ctx->memcached_key_prefix.len > 0)
            (void) ngx_copy(ctx->memcached_key_real.data, ctx->memcached_key_prefix.data,
                     ctx->memcached_key_prefix.len);
    }

    /* calculate key */
    if (ctx->memcached_key.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "ngx_http_xsltproc_memcached_get() calculate key");

        ngx_md5_init(&md5);

        for (cl = in; cl; cl = cl->next) {
            ngx_md5_update(&md5, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }

        for (i = 0; i < ctx->sheets->nelts; i++) {
            xslt_stylesheet = sheet[i].xslt_stylesheet;
            ngx_md5_update(&md5, xslt_stylesheet->uri, ngx_strlen(xslt_stylesheet->uri));
            ngx_md5_update(&md5, &xslt_stylesheet->mtime, sizeof(time_t));

            params = sheet[i].params.elts;
            for (j = 0; j < (sheet[i].params.nelts - 1); j++) {
                ngx_md5_update(&md5, params[j], ngx_strlen(params[j]));
            }
        }

        ngx_md5_final(md5_buf, &md5);

        ngx_hex_dump(&ctx->memcached_key_real.data[ctx->memcached_key_prefix.len], md5_buf, 16);
    }
    else {
        (void) ngx_copy(&ctx->memcached_key_real.data[ctx->memcached_key_prefix.len],
                 ctx->memcached_key.data, ctx->memcached_key.len);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "ngx_http_xsltproc_memcached_get() key: '%V'", &ctx->memcached_key_real);

    value = (xmlChar *) memcached_get(ctx->memcached, (const char *)ctx->memcached_key_real.data,
        ctx->memcached_key_real.len, &value_length, &flags, &memcached_return);

    if (memcached_return != MEMCACHED_SUCCESS) {
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "ngx_http_xsltproc_memcached_get() found key: '%V' data size: %d",
                  &ctx->memcached_key_real, value_length);

    /* mark buffers as completed */
    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
    }

    doc_type        = (int) flags;
    b               = NULL;
    xslt_stylesheet = sheet[ctx->sheets->nelts - 1].xslt_stylesheet;

    if (ngx_http_xsltproc_apply_encoding(r, xslt_stylesheet, doc_type) == NGX_OK) {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            ngx_free(value);
            return NULL;
        }

        b->pos    = (u_char *) value;
        b->last   = (u_char *) (value + value_length);
        b->memory = 1;

        if (r == r->main) {
            b->last_buf = 1;
        }
    }

    return b;
}

static void
ngx_http_xsltproc_memcached_set(ngx_http_request_t *r, ngx_buf_t *b, int doc_type,
                                ngx_http_xsltproc_filter_ctx_t *ctx)
{
    memcached_return_t memcached_return;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "ngx_http_xsltproc_memcached_set() key: '%V' data size: %d",
                  &ctx->memcached_key_real, b->last - b->pos);

    memcached_return = memcached_set(ctx->memcached, (const char *)ctx->memcached_key_real.data,
        ctx->memcached_key_real.len, (char *) b->pos, b->last - b->pos, ctx->memcached_expire, doc_type);

    if (memcached_return != MEMCACHED_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_xsltproc_memcached_set() failure");
    }
}
#endif

static ngx_int_t
ngx_http_xsltproc_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                                  wellFormed, doc_type = 0;
    ngx_chain_t                         *cl;
    ngx_http_xsltproc_filter_ctx_t      *ctx;
    ngx_buf_t                           *b;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xsltproc_filter_module);

    if (ctx == NULL || ctx->sheets->nelts == 0 || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

#if (NGX_HTTP_XSLTPROC_MEMCACHED)
    if (ctx->memcached != NULL && ctx->memcached_done == 0) {
        b = ngx_http_xsltproc_memcached_get(r, in, ctx);

        if (b != NULL)
            return ngx_http_xsltproc_send(r, ctx, b);
    }
#endif

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
                b = ngx_http_xsltproc_apply_stylesheet(r, ctx, &doc_type);

#if (NGX_HTTP_XSLTPROC_MEMCACHED)
                if (ctx->memcached != NULL && b != NULL) {
                    ngx_http_xsltproc_memcached_set(r, b, doc_type, ctx);
                }
#endif

                return ngx_http_xsltproc_send(r, ctx, b);
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

    if (ctx->done == 0) {
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

    ctx->done = 1; /* stop further chunk parsing */
}

static ngx_int_t
ngx_http_xsltproc_apply_encoding(ngx_http_request_t *r,
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet, int doc_type)
{
    ngx_str_t *type, *encoding;

    encoding = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (encoding == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(encoding, sizeof(ngx_str_t));

    type = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (type == NULL) {
        return NGX_ERROR;
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

    if (encoding->data) {
        r->headers_out.charset.len  = encoding->len;
        r->headers_out.charset.data = encoding->data;
    }

    if (r != r->main) {
        return NGX_OK;
    }

    if (type->data) {
        r->headers_out.content_type.len  = type->len;
        r->headers_out.content_type.data = type->data;

    } else if (doc_type == XML_HTML_DOCUMENT_NODE) {

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&r->headers_out.content_type, "text/html");
    }

    r->headers_out.content_type_lowcase = NULL;

    return NGX_OK;
}


static ngx_buf_t *
ngx_http_xsltproc_apply_stylesheet(ngx_http_request_t *r,
    ngx_http_xsltproc_filter_ctx_t *ctx, int *doc_type)
{
    int                                   len, rc;
    ngx_buf_t                            *b;
    ngx_uint_t                            i;
    xmlChar                              *buf;
    xmlDocPtr                             doc, res;
    ngx_http_xsltproc_sheet_t            *sheet;
    ngx_http_xsltproc_filter_loc_conf_t  *conf;
    ngx_http_xsltproc_xslt_stylesheet_t  *xslt_stylesheet = NULL;

    conf  = ngx_http_get_module_loc_conf(r, ngx_http_xsltproc_filter_module);
    sheet = ctx->sheets->elts;
    doc   = ctx->doc;

#if (NGX_HTTP_XSLTPROC_PROFILER)
    if (conf->profiler == 1 && conf->profiler_stylesheet) {
        ngx_http_xsltproc_xslt_profiler_init(ctx->profiler);
    }
#endif

    for (i = 0; i < ctx->sheets->nelts; i++) {
        xslt_stylesheet = sheet[i].xslt_stylesheet;

#if (NGX_HTTP_XSLTPROC_PROFILER)
        res = ngx_http_xsltproc_xslt_transform(xslt_stylesheet, doc,
            sheet[i].params.elts, conf->profiler, ctx->profiler);
#else
        res = ngx_http_xsltproc_xslt_transform(xslt_stylesheet, doc,
            sheet[i].params.elts);
#endif
        xmlFreeDoc(doc);

        if (res == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xsltApplyStylesheet() failed");
            return NULL;
        }

        doc = res;
    }

#if (NGX_HTTP_XSLTPROC_PROFILER)
    if (conf->profiler == 1 && conf->profiler_stylesheet) {
        ngx_http_xsltproc_xslt_profiler_done(ctx->profiler, conf->profiler_stylesheet, doc);
    }
#endif

    /* there must be at least one stylesheet */

    *doc_type = doc->type;

    rc = xsltSaveResultToString(&buf, &len, doc, xslt_stylesheet->stylesheet);

    xmlFreeDoc(doc);

    if (ngx_http_xsltproc_apply_encoding(r, xslt_stylesheet, *doc_type) != NGX_OK) {
        return NULL;
    }

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

    b->pos    = buf;
    b->last   = buf + len;
    b->memory = 1;

    if (r == r->main) {
        b->last_buf = 1;
    }

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


#if (NGX_HTTP_XSLTPROC_PROFILER)
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

#if (NGX_HTTP_XSLTPROC_MEMCACHED)
static void
ngx_http_xsltproc_cleanup_memcached(void *data)
{
     memcached_free(data);
}

static char *
ngx_http_xsltproc_memcached_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xsltproc_filter_loc_conf_t *xlcf = conf;
    ngx_pool_cleanup_t                  *cln;
    ngx_url_t                            u;
    ngx_str_t                           *value;
    char                                *tmp;

    if (xlcf->memcached == NULL) {
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        xlcf->memcached = memcached_create(NULL);

        if (xlcf->memcached == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "memcached_create() failed");
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_http_xsltproc_cleanup_memcached;
        cln->data    = xlcf->memcached;
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url        = value[1];
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in memcached server \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    tmp = ngx_pnalloc(cf->pool, u.host.len + 1);
    if (tmp == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(tmp, u.host.data, u.host.len);
    tmp[u.host.len] = '\0';

    if (u.family == AF_UNIX) {
        memcached_server_add_unix_socket(xlcf->memcached, tmp);
    }
    else {
        memcached_server_add(xlcf->memcached, tmp, u.port);
    }

    return NGX_CONF_OK;
}
#endif


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
#if (NGX_HTTP_XSLTPROC_PROFILER)
    conf->profiler                   = NGX_CONF_UNSET;
    conf->profiler_repeat            = NGX_CONF_UNSET;
#endif
#if (NGX_HTTP_XSLTPROC_MEMCACHED)
    conf->memcached_enable           = NGX_CONF_UNSET;
    conf->memcached_key_auto         = NGX_CONF_UNSET;
    conf->memcached_expire           = NGX_CONF_UNSET;
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

#if (NGX_HTTP_XSLTPROC_PROFILER)
    ngx_conf_merge_value(conf->profiler,
        prev->profiler, 0);

    ngx_conf_merge_value(conf->profiler_repeat,
        prev->profiler_repeat, 0);

    if (conf->profiler_stylesheet == NULL)
        conf->profiler_stylesheet = prev->profiler_stylesheet;
#endif

#if (NGX_HTTP_XSLTPROC_MEMCACHED)
    ngx_conf_merge_value(conf->memcached_enable,
        prev->memcached_enable, 0);

    ngx_conf_merge_str_value(conf->memcached_key_prefix,
        prev->memcached_key_prefix, "");

    ngx_conf_merge_value(conf->memcached_key_auto,
        prev->memcached_key_auto, 0);

    ngx_conf_merge_value(conf->memcached_expire,
        prev->memcached_expire, 0);
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
