from html.parser import HTMLParser
from pathlib import Path
import json
class Page(HTMLParser):
 def __init__(self): super().__init__();self.ids=[];self.links=[];self.h1=0;self.scripts=0;self.images=[]
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'id' in a:self.ids.append(a['id'])
  if tag=='a':self.links.append(a.get('href',''))
  if tag=='h1':self.h1+=1
  if tag=='script':self.scripts+=1
  if tag=='img':self.images.append(a)
p=Page();p.feed(Path(__file__).with_name('index.html').read_text())
assert len(p.ids)==len(set(p.ids))
assert p.h1==1 and p.scripts==0
assert all(x[1:] in p.ids for x in p.links if x.startswith('#'))
assert all(a.get('alt') is not None for a in p.images)
def lum(h):
 rgb=[int(h[i:i+2],16)/255 for i in (0,2,4)]
 rgb=[n/12.92 if n<=.04045 else ((n+.055)/1.055)**2.4 for n in rgb]
 return sum(n*w for n,w in zip(rgb,[.2126,.7152,.0722]))
def ratio(a,b):
 x,y=sorted([lum(a),lum(b)]);return round((y+.05)/(x+.05),2)
contrasts={name:ratio(a,b) for name,a,b in [('body','243a30','f5f3eb'),('muted','59665c','f5f3eb'),('amber','875a28','f5f3eb'),('card copy','536150','e9ece2'),('dark CTA','fffdf4','243a30'),('footer eyebrow','d7b57f','243a30')]}
assert min(contrasts.values())>=4.5
print(json.dumps({'static_checks':'pass','one_h1':True,'duplicate_ids':False,'internal_links':'all resolve','client_javascript':False,'contrast_ratios':contrasts, 'browser_and_accessibility_qa':'not checked by this script'},indent=2))
