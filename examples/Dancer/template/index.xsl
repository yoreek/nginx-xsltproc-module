<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="layouts/default.xsl" />

<xsl:template name="body">
    <h3><xsl:value-of select="/root/msg" /></h3>
</xsl:template>

</xsl:stylesheet>
