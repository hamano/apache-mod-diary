
#define RSS_TMPL \
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"\
"<rss version=\"2.0\">\n"\
" <channel>\n"\
"  <title><?cs var:html_escape(diary.title) ?></title>\n"\
"  <description></description>\n"\
"  <link><?cs var:diary.uri ?></link>\n"\
"<?cs each:item = index ?>"\
"  <item>\n"\
"   <link><?cs var:item.uri ?></link>\n"\
"   <title><?cs var:html_escape(item.title) ?></title>\n"\
"<?cs if:item.desc ?>"\
"   <description>"\
"     <![CDATA[<?cs var:html_escape(item.desc) ?>]]>"\
"   </description>\n"\
"<?cs /if ?>"\
"  </item>\n"\
"<?cs /each ?>"\
" </channel>\n"\
"</rss>\n"

#define RSS_TMPL_LEN (sizeof(RSS_TMPL) - 1)
