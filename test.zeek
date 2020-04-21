global count404:count=0;
global countAll:count=0;
global countUrl:count=0;
global url:string;
global Allurl:set[string];
global orig_h:addr;
global last_ts:time;
global net_ts:time;
global con:bool=F;
event http_header(c:connection,is_orig:bool,name:string,value:string)
{
	orig_h=c$id$orig_h;
	if(name=="REFERER")
	url=value;
	
}
event http_reply(c:connection,version:string,code:count,reson:string)
	{
	net_ts=network_time();
	if(con)
	{
		if((net_ts-last_ts)>10 mins)
		{
			count404=0;
			countAll=0;
			countUrl=0;
			local temp:string;
			for(temp in Allurl)
				delete Allurl[temp];
		}
	}
	else
	{
		con=T;
		last_ts=net_ts;
	}
  ++countAll;
  if (code==404)
    {
      ++count404;
      if(!(url in Allurl))
      {
    	add Allurl[url];
    	++countUrl;
      }
      
    }
	}
event zeek_done()
  {
  if(count404>2)
  {
	if(count404/countAll>0.2)
	{
		if(countUrl/count404>0.5)
		{
			print fmt("%s is a scanner with %d scan attemps on %d urls",orig_h,count404,countUrl);
		}
	}
  }
  }
