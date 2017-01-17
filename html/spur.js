function go(d,a){
  if(!validNavAddress(d)){
    error.innerHTML='The specified NAV Address is not valid.';
  } else {
    error.innerHTML="Retrieving public key...";
    getJSON("http://"+window.location.hostname+"/api/do=getPubKey",function(err, res){
      if(err){
        error.innerHTML="ERROR: "+err+". Please, try again later.";
      } else if(res.err != ""){
        error.innerHTML=res.err;
      } else {
        error.innerHTML="";
        if(confirm('You are about to send '+a+'NAV to the following address:\n\n'+d+'\n\nIt will apply a '+res.fee+'% fee.\n\nAre you sure? Please double check that everything is ok!! This will be encrypted before leaving your computer and won\'t be further verifiable.') == true){
          kbpgp.KeyManager.import_from_armored_pgp({
            armored: res.pubKey
          }, function(err, spur) {
            if (!err) {
              kbpgp.box({msg: a+'#######'+d, encrypt_for: spur}, function(err, result_armored_string, result_raw_buffer) {
                error.innerHTML="Connecting with the server...";
                getJSON("http://"+window.location.hostname+"/api/do=newAddress&data="+encodeURIComponent(result_armored_string),function(err, res){
                  if(err){
                    error.innerHTML="ERROR: "+err+". Please, try again later.";
                  } else if(res.err != ""){
                    error.innerHTML=res.err;
                  } else {
                    error.innerHTML="";
                    document.location.href="http://"+window.location.hostname+"/spur.html?"+res.id;
                  }
                });
              });
            }
          });
        }
      }
    });
  }
}

function waiting(id){
  getJSON("http://"+window.location.hostname+"/api/do=checkTx&id="+id,function(err, res){
    if(err){
      error.innerHTML="ERROR: "+err+". Please, try again later.";
    } else if(res.err == "Expired."){
      error.innerHTML="";
      header_content.innerHTML="<h1>EXPIRED</h1><p>The transaction was initiated more than 6h ago. Please initiate a new one <a href=\"http://"+window.location.hostname+"/\">here</a>.";
    } else if(res.err != ""){
      error.innerHTML=res.err;
    } else {
      error.innerHTML="";
      header_content.innerHTML="<h1>OK.</h1><br><p>Please send "+res.amount+"NAV ("+res.value+"NAV + "+parseFloat(res.fee)+"% fee) to the following address:<br/><br/><strong>"+res.addr+"<strong><br/><br/><div id=\"balance\">The transaction will expire after "+parseInt(res.expires/3600)+" hours, "+parseInt((res.expires%3600)/60)+" minutes and "+parseInt((res.expires%3600)%60)+" seconds. <br><br>Amount received: 0NAV</div><br><br><span class=\"mini\">This page will update as soon as the transaction is confirmed.<br>Please transfer the full amount of NAVs before it expires.<br><br><a target=\"_blank\" href=\"http://"+window.location.hostname+"/spur.html\">Home page</a> | <a target=\"_blank\" href=\"https://chainz.cryptoid.info/nav/address.dws?"+res.addr+".htm\">Blockchain Explorer</a> | <a target=\"_blank\" href=\"http://"+window.location.hostname+"/spur.html?"+id+"\">Permalink</a> </span>";
      checkBalance(id)
    }
  })

}

function checkBalance(i){
  var again = 1;
  getJSON("http://"+window.location.hostname+"/api/do=checkAddr&id="+i,function(err, res){
    if(err){
      error.innerHTML="ERROR: "+err;
    } else if(res.err != ""){
      error.innerHTML=res.err;
    } else {
      error.innerHTML="";
      balance.innerHTML="The transaction will expire after "+parseInt(res.expires/3600)+" hours, "+parseInt((res.expires%3600)/60)+" minutes and "+parseInt((res.expires%3600)%60)+" seconds.<br><br>Amount received: "+res.val+"NAV";
      if(res.val >= res.expected){
        if(res.status == 1){
          header_content.innerHTML="<h1>DONE!</h1><p>We safely received your NAVs and forwarded them through our anon servers.</p><br><br><a href=\"http://"+window.location.hostname+"/spur.html\">MAKE ANOTHER TRANSACTION.</a>";
          again = 0;
        } else {
          balance.innerHTML="We received the total amount of NAVs. We will proceed to anonymise them through our servers.<br><br>Amount received: "+res.val+"NAV.";
        }
      }
    }

    if(again == 1){
      setTimeout(function() {
        checkBalance(i);
      }, 30000);
    }
  });
}

function validNavAddress(address) {
  var error = 0, b58;

  try {
    b58 = base58.decode(address);
  } catch(e){
    error = 1;
  }

  return (address.length == 34) && b58 && b58[0] == 0x35 && error == 0;
}

var getJSON = function(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open("get", url, true);
    xhr.responseType = "json";
    xhr.onload = function() {
      var status = xhr.status;
      if (status == 200) {
        callback(null, xhr.response);
      } else {
        callback(status);
      }
    };
    xhr.send();
};


// base-x encoding
// Forked from https://github.com/cryptocoinjs/bs58
// Originally written by Mike Hearn for BitcoinJ
// Copyright (c) 2011 Google Inc
// Ported to JavaScript by Stefan Thomas
// Merged Buffer refactorings from base58-native by Stephen Pair
// Copyright (c) 2013 BitPay Inc

function basex (ALPHABET) {
   var ALPHABET_MAP = {}
   var BASE = ALPHABET.length
   var LEADER = ALPHABET.charAt(0)
   var me = {}

   // pre-compute lookup table
   for (var z = 0; z < ALPHABET.length; z++) {
     var x = ALPHABET.charAt(z)

     if (ALPHABET_MAP[x] !== undefined) throw new TypeError(x + ' is ambiguous')
     ALPHABET_MAP[x] = z
   }

   me.encode = function (source) {
     if (source.length === 0) return ''

     var digits = [0]
     for (var i = 0; i < source.length; ++i) {
       for (var j = 0, carry = source[i]; j < digits.length; ++j) {
         carry += digits[j] << 8
         digits[j] = carry % BASE
         carry = (carry / BASE) | 0
       }

       while (carry > 0) {
         digits.push(carry % BASE)
         carry = (carry / BASE) | 0
       }
     }

     var string = ''

     // deal with leading zeros
     for (var k = 0; source[k] === 0 && k < source.length - 1; ++k) string += ALPHABET[0]
     // convert digits to a string
     for (var q = digits.length - 1; q >= 0; --q) string += ALPHABET[digits[q]]

     return string
   }

  me.decodeUnsafe = function (string) {
     if (string.length === 0) return []

     var bytes = [0]
     for (var i = 0; i < string.length; i++) {
       var value = ALPHABET_MAP[string[i]]
       if (value === undefined) return

       for (var j = 0, carry = value; j < bytes.length; ++j) {
         carry += bytes[j] * BASE
         bytes[j] = carry & 0xff
         carry >>= 8
       }

       while (carry > 0) {
         bytes.push(carry & 0xff)
         carry >>= 8
       }
     }

     // deal with leading zeros
     for (var k = 0; string[k] === LEADER && k < string.length - 1; ++k) {
       bytes.push(0)
     }

     return bytes.reverse()
   }

   me.decode = function (string) {
     var buffer = me.decodeUnsafe(string)
     if (buffer) return buffer

     throw new Error('Non-base' + BASE + ' character')
   }

   return me;
 }

 var base58 = basex('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
