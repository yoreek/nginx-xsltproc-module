<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output
    media-type="text/html" method="xml" encoding="utf-8"
    omit-xml-declaration="yes"
    doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
    indent="yes"
/>

<xsl:template match="/">
    <html>
        <head><xsl:call-template name="head" /></head>
        <body><xsl:call-template name="body" /></body>
    </html>
</xsl:template>

<xsl:template name="head">
    <title><xsl:value-of select="/root/title" /></title>
</xsl:template>

<!-- Need to override -->
<xsl:template name="body" />

</xsl:stylesheet>
