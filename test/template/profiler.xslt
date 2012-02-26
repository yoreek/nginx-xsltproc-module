<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output
	media-type="text/html" method="xml" encoding="utf-8"
	omit-xml-declaration="yes"
	indent="yes"
/>

<!--
        /*
         * <profiler>
         *   <stylesheet uri="main.xsl">
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
-->

<xsl:template match="/profiler">
	<xsl:variable name="total" select="format-number(sum(stylesheet/profile/template/@time) div 100, '#.##')" />

	<div id="profiler" class="profiler">
		<ul>
			<li class="closed"><label><xsl:value-of select="concat('Profiler (', $total,' ms)')" /></label>
				<ul><xsl:apply-templates /></ul>
			</li>
		</ul>
		<link rel="stylesheet" type="text/css" href="/css/profiler.css" />
		<script type="text/javascript" src="/js/profiler.js"></script>
	</div>
</xsl:template>

<xsl:template match="stylesheet">
	<xsl:variable name="total" select="format-number(sum(profile/template/@time) div 100, '#.##')" />

	<li><label><strong>Stylesheet:</strong> <xsl:value-of select="concat(@uri, ' (', $total,' ms)')" /></label>
		<ul><xsl:apply-templates /></ul>
	</li>
</xsl:template>

<xsl:template match="profile">
	<li><label><strong>Profile</strong></label>
		<ul><li class="node-text">
			<table>
				<tr><th>Rank</th><th>Match</th><th>Name</th><th>Mode</th><th>Calls</th><th>Time (ms)</th><th>Avg (ms)</th></tr>
				<xsl:for-each select="template">
					<tr>
						<td><xsl:value-of select="@rank" /></td>
						<td><xsl:value-of select="@match" /></td>
						<td><xsl:value-of select="@name" /></td>
						<td><xsl:value-of select="@mode" /></td>
						<td><xsl:value-of select="@calls" /></td>
						<td><xsl:value-of select="format-number(@time div 100, '#.##')" /></td>
						<td><xsl:value-of select="format-number(@time div @calls div 100, '#.##')" /></td>
					</tr>
				</xsl:for-each>
			</table>
		</li></ul>
	</li>
</xsl:template>

<xsl:template match="document">
	<li class="closed"><label><strong>XML</strong></label>
		<ul>
			<xsl:apply-templates mode="xml" />
		</ul>
	</li>
</xsl:template>

<xsl:template mode="xml" match="*">
	<li class="closed">
		<label>
			<xsl:attribute name="title">
				<xsl:call-template name="node-path" />
			</xsl:attribute>
			&lt;<b><xsl:value-of select="name()" /></b>&gt;<xsl:apply-templates mode="attr" select="@*" /></label>
		<ul><xsl:apply-templates mode="xml" /></ul>
		<label>&lt;/<b><xsl:value-of select="name()" /></b>&gt;</label>
	</li>
</xsl:template>

<xsl:template mode="xml" match="*[count(*) = 0]">
	<li class="node-text">
		<label>
			<xsl:attribute name="title">
				<xsl:call-template name="node-path" />
			</xsl:attribute>
			&lt;<b><xsl:value-of select="name()" /></b>&gt;<xsl:apply-templates mode="attr" select="@*" /></label>
		<xsl:value-of select="." />
		<label>&lt;/<b><xsl:value-of select="name()" /></b>&gt;</label>
	</li>
</xsl:template>

<xsl:template mode="attr" match="@*">
	<xsl:text> </xsl:text><s><xsl:value-of select="name()" /></s>="<i><xsl:value-of select="." /></i>"
</xsl:template>

<xsl:template name="node-path">
	<xsl:for-each select="ancestor-or-self::node()[position() &lt; (last() -3)]">
		<xsl:value-of select="concat('/', name())"/>
	</xsl:for-each>
</xsl:template>

<xsl:template match="params">
	<li class="closed"><label><strong>Params</strong></label>
		<ul><li class="node-text">
			<table>
				<tr><th>Name</th><th>Value</th></tr>
				<xsl:for-each select="param">
					<tr>
						<td><xsl:value-of select="@name" /></td>
						<td><xsl:value-of select="@value" /></td>
					</tr>
				</xsl:for-each>
			</table>
		</li></ul>
	</li>
</xsl:template>

</xsl:stylesheet>
