::  S3 authentication
::
::::  /hoon/s3-auth/lib
  ::
/+  s3
|%
++  keys  cord:{key/@t sec/@t}                          ::  app key pair
++  region
  $?  $us-east-2
      $us-east-1
      $us-west-1
      $us-west-2
      $ca-central-1
      $ap-south-1
      $ap-northeast-1
      $ap-northeast-2
      $ap-southeast-1
      $ap-southeast-2
      $eu-west-1
      $eu-west-2
      $sa-east-1
  ==
:: ganked from ~palfun
++  trim-left
  |=  str/tape
  ^-  tape
  (scan str ;~(pfix spac:poja (star next)))
::
++  glue
  |=  {pieces/(list tape) delim/tape}
  ^-  tape
  %+  roll  pieces
  |=  {piece/tape str/tape}
  ?~  str  piece
  :(welp str delim piece)
::
::  Trim whitespace off string right-side.
++  trim-right
  |=  str/tape
  ^-  tape
  ::TODO  Be less lazy, maybe.
  %-  flop
  (trim-left (flop str))
::
::  Trim whitespace off string ends.
++  trim
  |=  str/tape
  ^-  tape
  (trim-left (trim-right str))
++  dsig
  "dummy sig"
++  dpol
  "dummy pol"
:: sha-256
++  catip
  |=  {a/@t b/@t}
  ^-  @t
  (crip (welp (trip a) (trip b)))
::  RFC-888
++  rfce
  |=  d/@d
  ^-  tape
  %+  welp
    %+  scag
      26
    %-  dust
    %-  yore
    d
  "GMT"
::  ISO8601
::
++  esoo
  |=  d/@d
  ^-  tape
  =/  t  (yore d)
  ;:  welp
      (scag 1 (scow %ud y.t))
      (swag [2 3] (scow %ud y.t))
      (double m.t)
      (double d.t.t)
      "T"
      (double h.t.t)
      (double m.t.t)
      (double s.t.t)
      "000Z"
  ==
:: ud to leading zero tape
++  double
  |=  a/@ud
  ^-  tape
  =/  x  (scow %ud a)
  ?:  (lth a 10)
    (welp "0" x)
  x
::++  create-policy
++  signing-key
  |=  {tim/@da key/@t reg/region}
  ^-  @t
  %+  hmc:scr  
    %+  hmc:scr
      %+  hmc:scr
        %+  hmc:scr
          %+  catip  
            'AWS4'
          key
        (crip (swag [0 8] (esoo tim)))
      reg
    's3'
  'aws4_request'
++  encode-policy
  |=  j/json
  (sifo (crip (pojo j)))
++  hed-form
  |=  {a/@t b/@t}
  "{(cass (trip a))}:{(trim (trip b))}"
++  cat-list
  |=  a/(list @t)
  ^-  tape
  =/  b  ""
  |-
  ?~  a  b
  $(b (weld b (trip -.a)), a +.a)
++  sined-hed
  |=  hed/math
  ^-  tape
  %+  glue
    (turn (map-keys hed) |=(a/@t (trip a)))
  ";"
:: join list of key-vals into header format
++  to-header
  |=  a/(list {@t @t})
  ^-  @t
  %-  crip
  %+  glue
    %+  turn
      a
    |=(b/{x/@t y/@t} "{(trip x.b)}={(trip y.b)}")
  ","
++  can-query
  |=  a/quay 
  ^-  tape
  %+  glue
    %+  turn
      %+  sort
        a
      aor
    |=  {b/@t c/@t}
    "{(urle (trip b))}={(urle (trip c))}"
  "&"
++  map-keys
  |=  a/math
  ^-  (list @t)
  %+  sort
    %-  %~  tap
            in
            %~  key
                by
                a
            ==
        ==
    ~
  aor
++  hedders
  |=  hed/math
  ^-  tape
  %+  glue
    %^    spin  
        (map-keys hed)
      |=  {a/@t n/math}
      :-  %+  hed-form
            a
          =/  b  (~(got by n) a)
          ?~  b  ''
          -.b
      n
    hed
  "\0a"
:: tape of resource
++  can-uri
  |=  a/purl
  ^-  tape
  ;:  welp
      "/{(urle (slag 1 (trip (spat q.q.a))))}"
      "."
      ?~  p.q.a  ""
      (trip (need p.q.a))
  ==
:: hex of sha256
++  hax
  |=  a/@t
  ^-  @t
    %-  crip
    %+  slag
      2
    %+  scow
      %ux
    %+  swap
      3
    %-  shax
    a
++  cred
  |=  {key/@t tim/@da reg/region}
  ^-  @t
  %-  crip
  %+  glue
    :~  (trip key)
        (swag [0 8] (esoo tim))
        (trip reg)
        "s3"
        "aws4_request"
    ==
  "/"
++  payload-hash
  |=  a/(unit octs)
  %-  hax
  ?~  a  ''
  q.u.a
:: canonical request
++  can-req
  |=  req/hiss
  ^-  @t
  %-  role  
  :~  (crip "{(cuss (trip p.q.req))}")
      (crip (can-uri p.req))
      (crip (can-query r.p.req))
      (crip (hedders q.q.req))
      (crip (sined-hed q.q.req))
      (payload-hash r.q.req)
  ==
::  string to sign
++  sign-string
  |=  {cr/@t t/@da reg/region}
  ^-  @t
  =/  ti  (esoo t)
  %-  role
  :~  'AWS4-HMAC-SHA256'
      (crip ti)
      %-  crip
      %+  glue
        :~  %+  swag
              [0 8]
            ti
            ~&  (trip reg)
            (trip reg)
            "s3/aws4_request"
        ==
      "/"
      (hax cr)
  ==
++  signature
  |=  {req/hiss tim/@da reg/region sec/@t}
  ^-  @t
  %-  crip
  %+  slag
    2
  %+  scow
    %ux
  %+  swap
    3
  %+  hmc:scr 
    %^    signing-key
        tim
      sec
    reg
  %^    sign-string
      ~&  [%can-req (can-req req)]
      (can-req req)
    tim
  reg
--
::
::::
  ::
|_  {bal/(bale keys) $~}
::  key stuff
++  consumer-key     key:decode-keys
++  consumer-secret  sec:decode-keys
++  decode-keys                       :: XX from bale w/ typed %jael
  ^-  {key/@t sec/@t $~}
  ((hard {key/@t sec/@t $~}) (lore key.bal))
  ::?.  =(~ `@`keys)
  ::  ~|  %oauth-bad-keys
  ::%+  mean-wall  %oauth-no-keys
  ::"""
  ::Run |init-oauth1 {<`path`dom>}
  ::"""
++  auth
  |%
  ++  header
    |=  a/hiss
    ^-  @t
    %^    cat 
        3 
      'AWS4-HMAC-SHA256 ' 
    %-  to-header 
    :~  :-  'credential'
        (cred consumer-key now.bal %us-west-1)
        :-  'signedheaders'
        %-  crip
        %-  sined-hed
        q.q.a
        :-  'signature'
        %-  signature 
        :^    a 
            now.bal 
          %us-west-1 
        consumer-secret
    ==
  ++  content-header
    |=  a/hiss
    ^-  {@t @t}
    [%x-amz-content-sha256 (payload-hash r.q.a)]
  ++  date-header
    ^-  {@t @t}
    [%x-amz-date (crip (rfce now.bal))]
  --
::
++  add-header
  |=  {a/hiss key/@t val/@t}  
  ^-  hiss
  %_(a q.q (~(add ja q.q.a) key val))
::
++  add-auth-header
  |=  a/hiss  ^-  hiss
  ~&  auth+(earn p.a)
  ~&  content+(content-header:auth a)
  ~&  [%date date-header:auth]
  :: get the service and the region out of the query
  %_(a q.q (~(add ja q.q.a) %authorization (header:auth a)))
::
++  standard
  |%
  ++  out-adding-header
    |=  a/hiss  ^-  sec-move
    ::=/  r  (add-auth-header a)
    =/  b  (add-header a (content-header:auth a))
    =/  c  (add-header b date-header:auth)
    =/  r  (add-auth-header c)
    ~&  [%request r]
    [%send r]
  --
--
