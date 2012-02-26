<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output
    media-type="text/html" method="xml" encoding="utf-8"
    omit-xml-declaration="yes"
    doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
    indent="yes"
/>

<xsl:param name="tmpl" />
<xsl:param name="step" select="1" />

<xsl:template match="/">
    <html>
        <head>
            <title>Nginx vs xsltproc module</title>
        </head>
        <body>
            <h3>Nginx vs xsltproc module</h3>
            <ul>
                <li><a href="?tmpl=document">Caching of XML-files loaded using the function document()</a></li>
                <li><a href="?tmpl=keys">Caching of keys using the function key()</a></li>
            </ul>
            <xsl:call-template name="content" />
        </body>
    </html>
</xsl:template>

<!-- Need to override -->
<xsl:template name="content" />

</xsl:stylesheet>
