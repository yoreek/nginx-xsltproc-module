<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="main.xslt" />

<xsl:key name="test" match="/root/items/item" use="@id" />

<xsl:template name="content">
    <h3>Caching of keys</h3>

    <ul>
        <xsl:for-each select="document('xml/test.xml')">
            <xsl:call-template name="search_by_key_first_time" />
            <xsl:call-template name="search_by_key_second_time" />
        </xsl:for-each>
    </ul>

    <h5>Note: Before the test you must restart the Nginx to clear the cache.</h5>
    <h5>Note: Need to enable "xsltproc_stylesheet_caching" option in the configuration file.</h5>
</xsl:template>

<xsl:template name="search_by_key_first_time">
    <li>Search by key "id77777" first time: "<xsl:value-of select="key('test', 'id1')/@name" />"</li>
</xsl:template>

<xsl:template name="search_by_key_second_time">
    <li>Search by key "id77777" second time: "<xsl:value-of select="key('test', 'id1')/@name" />"</li>
</xsl:template>

</xsl:stylesheet>
