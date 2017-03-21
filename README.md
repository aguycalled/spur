# SPUR 

- Nav Anonymization Web Gateway
- Client side encryption using kbpgp (https://github.com/keybase/kbpgp)

## Cloning repo

```
    git clone http://www.github.com/aguycalled/spur
```
 
## Editing config file
```
    cd spur
    cp config/example.json config/default.json
    pico config/default.json
```    
- Edit file using your own parameters.

| Parameter | Value |
|:-----------|:-----------|
| payout_address | Collected local fees will be sent to this Nav address |
| extra_fee | Extra local fee in addition to the fee from the navtech server |
| number_confirmations | Number of confirmations required for a transaction. |
| incoming_host | Navtech incoming server host |
| incoming_port | Navtech incoming server port, normally 3000 |
| rpc_user | RPC Username, check navcoind configuration file |
| rpc_password | RPC Password, check navcoind configuration file |
| rpc_host | RPC server host, normally 127.0.0.1 |
| rpc_port | RPC server port, normally 44444 |
| db_file | Where the SQLite database will be stored |


## Installing dependencies
```
    npm install
```    
## Running
```
    node spur.js
```    
- Run in background with:
```
    forever start spur.js
```    
## Checking log 
```
    forever logs 0
```
## API description
 
- General use:

```
    /api/do=command&param1=value1&param2=value2
```
- Every call returns a JSON object including the key 'err'. Any error would be returned as value. Undefined value of the key means success in the operation.

### getPubKey

- Use: Obtain public key.
```
    /api/do=getPubKey
```
- Parameters
```
  None
```
- Returns

| Key | Value |
|:-----------|:-----------|
| pubKey | Public Key which should be used to encrypt amount and address before sending to the server. |
| fee | Fee of the navtech server + local spur fee |

### getNewAddress

- Use: Obtain a new Spur address where funds would be send.
```
    /api/do=getNewAddress&data=ENCRYPTED_DATA
```
- Parameters
 
| Key | Value |
|:-----------|:-----------|
| data | The result of the pgp encryption of the NAV amount and the destination address concatenated with ####### using the provided public key. PGP_ENCRYPT(amount + '#######' + destination, public_key |

- Returns

| Key | Value |
|:-----------|:-----------|
| id | Token id of the spur transaction. |
| addr | Spur address where funds should be sent |
| amount | Nav amount with fee |
| value | Nav amount without fee |
| fee | Fee of the navtech server + local spur fee |

### checkTx

- Use: Obtain information about a transaction.
```
    /api/do=checkTx&id=token_id
```
- Parameters

| Key | Value |
|:-----------|:-----------|
| id | The token id of the transaction as returned by getNewAddress |

- Returns

| Key | Value |
|:-----------|:-----------|
| id | Token id of the spur transaction. |
| addr | Spur address where funds should be sent |
| amount | Nav amount with fee |
| value | Nav amount without fee |
| fee | Fee of the navtech server + local spur fee |
| expires | Number of seconds until expiration of the transaction |

### checkAddr

- Use: Obtain information about the current status of a transaction.
```
    /api/do=checkAddr&id=token_id
```
- Parameters

| Key | Value |
|:-----------|:-----------|
| id | The token id of the transaction as returned by getNewADdress |

- Returns

| Key | Value |
|:-----------|:-----------|
| val | Currently received amount. |
| amount | Expected amount. |
| status | 1: Received and forwarded 0: Not received/Not forwarded |
| expires | Number of seconds until expiration of the transaction |

