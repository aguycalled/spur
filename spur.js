const Client = require('bitcoin-core');
const http = require('http');
const https = require('https');
const querystring = require('querystring');
const sqlite = require('sqlite3').verbose();
const fs = require("fs");
const async = require('async');
const crypto = require('ursa');
const timestamp = require('unix-timestamp');
const kbpgp = require('kbpgp');

const config = require('config');
const file = config.get('db_file');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

var generatedPublicKey, generatedPrivateKey;

var db = new sqlite.Database(file);

var txPayoutAddress = config.get('payout_address');
var txFeeLocal = config.get('extra_fee') || 0;
var listen_port = config.get('listen_port') || 8080;
var min_amount = 10;
var max_amount = 10000;
var number_confirmations = config.get('number_confirmations') || 5;

var ready = 0;

navClient = new Client({

  username: config.get('rpc_user') || 'user',
  password: config.get('rpc_password') || 'password',
  port: config.get('rpc_port') || 44444,
  host: config.get('rpc_host') || '127.0.0.1',

})

if(!navClient)
{

  console.log("Error: Couldn't connect to rpc server "+config.get('rpc_host')+":"+config.get('rpc_port'))
  exit(-1)

}

const exists = fs.existsSync(file);

db.serialize(() =>
{

  if(!exists)
  {

    db.run("CREATE TABLE spur (date INT, src CHAR, dest CHAR, value FLOAT,amount FLOAT, fee FLOAT, flag1 FLOAT, flag2 INT, flag3 INT, flag4 CHAR, flag5 CHAR, flag6 CHAR)");

  }

});

console.log("Creating private/public key pair...")

var F = kbpgp["const"].openpgp;

kbpgp.KeyManager.generate({
  userid: "Spur <spur@spur.onion>",
  primary: {
    nbits: 4096,
    flags: F.certify_keys | F.sign_data | F.auth | F.encrypt_comm | F.encrypt_storage,
    expire_in: 0  // never expire
  },
  subkeys: [
    {
      nbits: 2048,
      flags: F.sign_data,
      expire_in: 86400 * 365 * 8 // 8 years
    }, {
      nbits: 2048,
      flags: F.encrypt_comm | F.encrypt_storage,
      expire_in: 86400 * 365 * 8
    }
  ]
}, (err, spur) =>
{
  if (!err)
  {

    spur.sign({}, (err) =>
    {

      spur.export_pgp_private ({
        passphrase: ''
      }, (err, pgp_private) =>
      {

        if(!err)
        {

          generatedPrivateKey = pgp_private;

          spur.export_pgp_public({}, (err, pgp_public) =>
          {

            if(!err)
            {

              generatedPublicKey = pgp_public;
              console.log("Testing keys...")

              var sampleText = "I believe the grass is no more greener on the other side."

              kbpgp.KeyManager.import_from_armored_pgp({
                armored: generatedPublicKey
              }, (err, testKey) =>
              {

                if (!err)
                {

                  kbpgp.box({msg: sampleText, encrypt_for: testKey}, (err, result_armored_string, result_raw_buffer) =>
                  {

                    kbpgp.KeyManager.import_from_armored_pgp({
                      armored: generatedPrivateKey
                    }, (err, testKeyPriv) =>
                    {

                      if (!err)
                      {

                        if (testKeyPriv.is_pgp_locked())
                        {

                          testKeyPriv.unlock_pgp({
                            passphrase: ''
                          }, (err) =>
                          {

                            if (!err)
                            {

                              var ring = new kbpgp.keyring.KeyRing;
                              ring.add_key_manager(testKeyPriv);

                              kbpgp.unbox({keyfetch: ring, armored: result_armored_string}, (err, literals) =>
                              {

                                if (err != null)
                                {

                                  console.log("PGP ERROR "+err)

                                }
                                else
                                {

                                  if (sampleText === literals[0].toString())
                                  {

                                    console.log("Starting SPUR")
                                    check();

                                  }
                                  else
                                  {

                                    console.log("Keys pair didn't pass test.")

                                  }
                                }
                              });

                            }
                            else
                            {

                              console.log("Error unlocking.")

                            }

                          });

                        }
                        else
                        {

                          console.log("Private key is not locked.")

                        }

                      }
                      else
                      {

                        console.log("Error importing private key.")

                      }

                    });

                  });

                }
                else
                {

                  console.log("Error testing Public Key.")

                }

              });

            }
            else
            {

              console.log("Error exporting Public key.")

            }

          });

        }
        else
        {

          console.log("Error exporting Private key.")

        }

      });

    });

  }
  else
  {

    console.log("Error adding key: "+err);

  }

});

function check()
{

  var post_data = "num_addresses=0"

  var post_options = {
      host: config.get('incoming_host'),
      port: config.get('incoming_port'),
      path: '/api/check-node',
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(post_data)
      }
  };

  var post_req = https.request(post_options,(res) =>
    {

    res.setEncoding('utf8');
    res.on('data', (chunk) =>
    {

      var json = JSON.parse(chunk);

      if(json.status == 200 && json.type == "SUCCESS")
      {

        txFee = json.data.transaction_fee;
        min_amount = json.data.min_amount;
        max_amount = json.data.max_amount;
        console.log("\nRemote Tx Fee: "+txFee+"\nMin amount: "+min_amount+"\nMax amount: "+max_amount+"\n\n")
        ready = 1;
        mainLoop();

      }
      else
      {

        setTimeout(check, 10000);

      }

    });

  });

  post_req.on('error', (err) =>
  {

    console.log("Err check(): "+err)
    setTimeout(check, 10000);

  })

  post_req.write(post_data);
  post_req.end();

}


function mainLoop()
{

  async.series([(callback) =>
    {

    db.get("SELECT COUNT(*) AS count FROM spur WHERE dest is NULL", (err,rows)=>
    {

      async.forEachLimit(Array(10 - rows.count), 1, (n, c) =>
      {

        navClient.getNewAddress().then((address) =>
        {

          console.log("Adding new Address to pool.");
          db.run("INSERT INTO spur (src) VALUES (?)", address);
          c();

        }).catch((e) =>
        {

          console.log("Fatal error: "+e);
          c();

        })

      }, (err) =>
      {

        callback();

      })

    })

  },
  (callback) =>
  {

    db.get("SELECT src FROM spur WHERE date IS NOT NULL AND date < ?", timestamp.now("-12h"), (err,rows)=>
    {

      if(err)
      {

        console.error("Err checkingexpired: "+err)

      }
      else if(rows && rows.length > 0)
      {

          db.run("DELETE FROM spur WHERE src = ?", n.src);

      }

      callback();

    });

  },
  (callback) =>
  {

    db.all("SELECT *  FROM spur WHERE (flag2 is NULL OR flag2 == 0) AND (dest IS NOT NULL)",
    (err,rows) =>
    {

      async.forEachLimit(rows, 1, (n, c) =>
      {

        navClient.getReceivedByAddress(n.src,number_confirmations)
        .then((received_amount) =>
        {

          db.run("UPDATE spur SET flag1 = ? WHERE src = ?", [received_amount,n.src]);
          if(received_amount >= n.amount)
          {

            var n_addr = 1;

            var post_data = "num_addresses="+n_addr;

            var post_options = {
                host: '176.9.19.245',
                port: '3000',
                path: '/api/check-node',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(post_data)
                }
            };

            var post_req = https.request(post_options, (res) =>
            {

              res.setEncoding('utf8');
              res.on('data', (chunk) =>
              {

                var json = JSON.parse(chunk);

                if(json.status == 200 && json.type == "SUCCESS")
                {

                  var anonAddr = json.data.nav_addresses;
                  var pubKey = json.data.public_key;

                  if(txFee !=  json.data.transaction_fee ||
                     min_amount != json.data.min_amount  ||
                     max_amount != json.data.max_amount)
                  {

                    console.log("\nRemote Tx Fee: "+txFee+"\nMin amount: "+min_amount+"\nMax amount: "+max_amount+"\n\n")

                  }

                  txFee = json.data.transaction_fee;
                  min_amount = json.data.min_amount;
                  max_amount = json.data.max_amount;

                  var pubKey = json.data.public_key;

                  var amountWithoutLocalFee = parseFloat(n.amount * (1+(txFee)/100)).toFixed(8) / parseFloat(1+(txFee+txFeeLocal)/100).toFixed(8)

                  if(n_addr == anonAddr.length)
                  {

                    async.forEachLimit(anonAddr, 1, (na, cb) =>
                    {

                      navClient.sendToAddress(na, parseFloat(amountWithoutLocalFee), null, null, n.dest).then((tx) =>
                      {

                        db.run("UPDATE spur SET flag2 = 1 WHERE src = ?",
                        n.src, (er) =>
                        {

                          if(er)
                          {

                            console.log("Err updatedbsendtoaddress: "+er)
                            cb();

                          }
                          else
                          {

                            var fee = parseFloat(n.amount - amountWithoutLocalFee).toFixed(8);

                            navClient.sendToAddress(txPayoutAddress, parseFloat(fee) - 0.0001, null, null, null,(tx) =>
                            {

                              console.log("Sending "+fee+" NAV to payout address. TX: "+tx)
                              cb();

                            }).catch((e) =>
                            {

                              console.log("Error sending fee to payout address: "+ e)
                              cb();

                            });

                          }

                        })

                      }).catch((e) =>
                      {

                        console.log("Fatal error: "+e);
                        cb();

                      });

                    }, (err) =>
                    {

                      c();

                    })

                  }
                  else
                  {

                    console.log("Err: We've asked for "+n_addr+" addresses but got instead "+anonAddr.length);
                    c();

                  }

                }
                else
                {

                  console.log("Err: Can't connect to Incoming Server");
                  c();

                }

              });

            });

            post_req.on('error', (err) =>
            {

              console.log("Err connectingtoincoming: "+ err);
              c();

            })

            post_req.write(post_data);
            post_req.end();

          }
          else
          {

            c();

          }

        })

      }, (err) =>
      {

        callback();

      })

    })

  }], (err, results) => {

    setTimeout(() => {

      mainLoop();

    },1000)

  })

}

function handleRequest(request, response){

  var query = request.url.split("/api/");

  var parametros = querystring.parse(query[1])

  if(ready == 0)
  {

    writeServer(response,{
      err:'Service in manteinance mode.'
    });

  }
  else if(parametros.do == "newAddress")
  {

    if(parametros.data)
    {

      parametros.data = decodeURI(parametros.data)

      kbpgp.KeyManager.import_from_armored_pgp({
        armored: generatedPrivateKey
      }, (err, pk) =>
      {

        if (!err)
        {

          if (pk.is_pgp_locked())
          {

              pk.unlock_pgp({
                passphrase: ''
              }, (err) =>
              {

                if (!err)
                {

                  var ring = new kbpgp.keyring.KeyRing;
                  ring.add_key_manager(pk);

                  kbpgp.unbox({keyfetch: ring, armored: parametros.data}, (err, literals) =>
                  {

                    if (err != null)
                    {

                      console.log("PGP ERROR "+err)

                      writeServer(response,{
                        err:'ERROR PGP Keys.'
                      });

                    }
                    else
                    {

                      parametros.data = literals[0].toString();

                      var data_parts = parametros.data.split('#######');

                      parametros.address = data_parts[1];
                      parametros.amount = data_parts[0];

                      navClient.validateAddress(parametros.address).then((result) =>
                      {

                        if(result.isvalid == false && result.ismine != false)
                        {

                          writeServer(response,{
                            err:'The specified NAV Address is not valid. (ERRCODE: 2)'
                          });

                        }
                        else if(parseFloat(parametros.amount) < min_amount ||
                              !(parseFloat(parametros.amount) > 0) ||
                                parseFloat(parametros.amount) > max_amount)
                        {

                            writeServer(response,{
                              err:'Amount should be between '+min_amount+'NAV and '+max_amount+'NAV.'
                            });

                        }
                        else
                        {

                          require('crypto').randomBytes(48, (err, buffer) =>
                          {

                            var token = buffer.toString('hex');
                            db.get("SELECT flag6 AS id, src AS addr FROM spur WHERE dest is NULL", (err,row) =>
                            {

                              var n_addr = 0;

                              var post_data = "num_addresses="+n_addr;

                              var post_options = {
                                  host: '176.9.19.245',
                                  port: '3000',
                                  path: '/api/check-node',
                                  method: 'POST',
                                  headers: {
                                      'Content-Type': 'application/x-www-form-urlencoded',
                                      'Content-Length': Buffer.byteLength(post_data)
                                  }
                              };

                              var post_req = https.request(post_options, (res) =>
                              {

                                res.setEncoding('utf8');
                                res.on('data', (chunk) =>
                                {

                                  var json = JSON.parse(chunk);

                                  if(json.status == 200 && json.type == "SUCCESS")
                                  {

                                    var anonAddr = json.data.nav_addresses;
                                    var pubKey = json.data.public_key;

                                    if(txFee !=  json.data.transaction_fee ||
                                       min_amount != json.data.min_amount  ||
                                       max_amount != json.data.max_amount)
                                    {

                                      console.log("\nRemote Tx Fee: "+txFee+"\nMin amount: "+min_amount+"\nMax amount: "+max_amount+"\n\n")

                                    }

                                    txFee = json.data.transaction_fee;
                                    min_amount = json.data.min_amount;
                                    max_amount = json.data.max_amount;

                                    var pubKey = json.data.public_key;

                                    var crt = crypto.createPublicKey(pubKey);

                                    var msg = crt.encrypt(parametros.address, 'utf8', 'base64',crypto.RSA_PKCS1_PADDING);

                                    db.run("UPDATE spur SET flag6 = ?, date = ?, fee = ?, dest = ?, value = ?, amount = ? WHERE src = ?", [
                                      token,
                                      parseInt(timestamp.now()),
                                      txFee+txFeeLocal,
                                      msg,
                                      parseFloat(parametros.amount).toFixed(8),
                                      parseFloat(parseFloat(parametros.amount).toFixed(8)*(1+((txFee+txFeeLocal)/100))).toFixed(8),
                                      row.addr
                                    ], (err) =>
                                    {

                                      if(!err)
                                      {

                                        row.fee = txFee+txFeeLocal;
                                        row.id = token;
                                        row.amount = parseFloat(parseFloat(parametros.amount).toFixed(8)*(1+((txFee+txFeeLocal)/100))).toFixed(8);
                                        row.value = parseFloat(parametros.amount).toFixed(8);
                                        row.err = "";
                                        writeServer(response,row);

                                      }
                                      else
                                      {

                                        writeServer(response,{
                                          err:'Please, try again later..'
                                        });

                                      }

                                    });

                                  }
                                  else
                                  {

                                    writeServer(response,{
                                      err:'Please, try again later..'
                                    });

                                  }

                                });

                              });

                              post_req.on('error', (err) =>
                              {

                                writeServer(response,{
                                  err:'Please, try again later..'
                                });

                              })

                              post_req.write(post_data);
                              post_req.end();



                            })

                          });

                        }

                      }).catch((e) =>
                      {

                        writeServer(response,{
                          err:'Please, try again later..'
                        });

                      })
                    }
                  });

                }
                else
                {

                  console.log("PGP ERROR "+err)
                  writeServer(response,{
                    err:'ERROR PGP Keys.'
                  });

                }

              });

          }

        }
        else
        {

          console.log("PGP ERROR "+err)
          writeServer(response,{
            err:'ERROR PGP Keys.'
          });

        }

      });

    }
    else
    {

      writeServer(response,{
        err:'Please indicate an address and an amount.'
      });

    }

  }
  else if(parametros.do == "checkTx")
  {

    if(parametros.id)
    {

      db.get("SELECT flag6 AS id, src AS addr, fee, amount, value, date FROM spur WHERE flag6 = ?",
        parametros.id, (err,row) =>
      {

        if(err)
        {

          writeServer(response,{
            err:'Please, try again later.'
          });

        }
        else if(row)
        {

          if(parseInt(row.date) > parseInt(timestamp.now("-12h")))
          {

            row.err = "";
            delete row.date;
            row.expires = parseInt((parseInt(row.date) + (60*60*6)) - timestamp.now());
            writeServer(response,row);

          }
          else
          {

            writeServer(response,{
              err:'Expired.'
            });

          }

        }
        else
        {

          writeServer(response,{
            err:'Wrong TX id.'
          });

        }

      })

    }
    else
    {

      writeServer(response,{
        err:'Wrong TX id.'
      });

    }

  }
  else if(parametros.do == "getPubKey")
  {

    var n_addr = 0;

    var post_data = "num_addresses="+n_addr;

    var post_options = {
        host: config.get('incoming_host'),
        port: config.get('incoming_port'),
        path: '/api/check-node',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(post_data)
        }

    };

    var post_req = https.request(post_options, (res) =>
    {

        res.setEncoding('utf8');
        res.on('data', (chunk) =>
        {

          var json = JSON.parse(chunk);

          if(json.status == 200 && json.type == "SUCCESS")
          {

            writeServer(response,{
              err:'', pubKey: generatedPublicKey, fee: json.data.transaction_fee + txFeeLocal
            });

          }
          else
          {

            writeServer(response,{
              err:'Can\'t connect to server, please try again later.'
            });

          }

        });

    });

    post_req.on('error', (err) =>
    {

      writeServer(response,{
        err:'Can\'t connect to server, please try again later.'
      });

    })

    post_req.write(post_data);
    post_req.end();

  }
  else if(parametros.do == "checkAddr")
  {

    if(parametros.id)
    {

      db.all("SELECT * FROM spur WHERE flag6 = ?",
      [parametros.id], (err,rows) =>
      {

        if(rows && rows.length > 0)
        {

          var expires = parseInt((parseInt(rows[0].date) + (60*60*6)) - timestamp.now());
          writeServer(response,{
            err:'',
            expires: expires,
            val:rows[0].flag1?rows[0].flag1:0,
            expected:rows[0].amount,
            status:rows[0].flag2?rows[0].flag2:0
          });

        }
        else
        {

          writeServer(response,{
            err:'Wrong Tx ID',
            val:0,
            expected:0
          });

        }

      });

    }
    else
    {

      writeServer(response,{
        err:'Please indicate an Tx ID.'
      });

    }

  }
  else
  {

    writeServer(response, {
      err:'Wrong call.'
    });

  }

};

var server = http.createServer(handleRequest);

server.listen(listen_port);

const writeServer = (r,j) =>
{

  if(r)
  {

    r.write(JSON.stringify(j));
    r.end();

  }

}

process.on('uncaughtException', (err) =>
{

  console.error((new Date).toUTCString() + ' uncaughtException:', err.message)
  console.error(err.stack)
  process.exit(1)

})
