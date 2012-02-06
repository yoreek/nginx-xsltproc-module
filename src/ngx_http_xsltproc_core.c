#include "ngx_http_xsltproc_core.h"

void *ngx_http_xsltproc_malloc(size_t size)
{
    void *p = malloc(size);
    if (p == NULL)
		perror("malloc failed\n");
    return p;
}

void ngx_http_xsltproc_free(void *p) {
	free(p);
}

time_t ngx_http_xsltproc_last_modify(const char *file_name) {
	struct stat sb;
	if (stat(file_name, &sb) == -1)
		return 0;
	return sb.st_mtime;
}
