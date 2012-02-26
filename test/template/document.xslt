<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="main.xslt" />

<xsl:template name="content">
    <h3>Caching of XML-files</h3>

    <ul>
        <xsl:call-template name="load_document_first_time" />
        <xsl:call-template name="load_document_second_time" />
    </ul>

    <h5>Note: Before the test you must restart the Nginx to clear the cache.</h5>
    <h5>Note: Need to enable "xsltproc_stylesheet_caching" option in the configuration file.</h5>
</xsl:template>

<xsl:template name="load_document_first_time">
    <li>Load document first time: "<xsl:value-of select="document('xml/test.xml')/root/@name" />"</li>
</xsl:template>

<xsl:template name="load_document_second_time">
    <li>Load document second time: "<xsl:value-of select="document('xml/test.xml')/root/@name" />"</li>
</xsl:template>

</xsl:stylesheet>
