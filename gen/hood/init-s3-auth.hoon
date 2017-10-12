::  API: input oauth1 application credentials for domain
::
::::  /hoon/init-s3-auth/hood/gen
  ::
/?  314
/-  sole
::
::::
  !:
[sole .]
:-  %ask
|=  $:  {now/@da eny/@uvJ bec/beak}
        {arg/$@($~ {dom/path $~})}
        $~
    ==
^-  (sole-result {$write-sec-atom p/host q/@})
=-  ?~  arg  -
    (fun.q.q [%& dom.arg])
%+  sole-lo
  [%& %oauth-hostname "api hostname: https://"]
%+  sole-go  thos:urlp
|=  hot/host
?:  ?=($| -.hot)
  ~|(%ips-unsupported !!)
%+  sole-lo
  [%& %oauth-client "Access Key ID: "]
%+  sole-go  (boss 256 (star prn))
|=  key/@t
%+  sole-lo  
  [%& %oauth-secret "Secret Key: "]
%+  sole-go  (boss 256 (star prn))
|=  sec/@t
%+  sole-so  %write-sec-atom    :: XX typed pair
[hot (role key sec ~)]
