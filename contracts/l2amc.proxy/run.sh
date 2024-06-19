c=amaxup.proxy

amcli convert pack_action_data -h

~/code/workspace/dex/ton4j/utils/src/test/java/org/ton/java/utils

pubKey: fc835dde75b3b579afe9425ef7184715ecd51a66c50f93e4b4b46291a3637508
pubKeyBase64: /INd3nWztXmv6UJe9xhHFezVGmbFD5PktLRikaNjdQg=
secKey: b9d067d274e8d82b2c4587d806988e42ad541e420fdcea57549af6c05fab620cfc835dde75b3b579afe9425ef7184715ecd51a66c50f93e4b4b46291a3637508
msg: ABC
msg hash: b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78 
msg sgin: 2b60542a308519a027ed53da537dbd9cdeee97851a2210d4e40f4a3aee1b05132775316fc366509c60e2ebdd3fa5dc18d9c72470461c5b46118891061492f808



msg= 0246adbdc438ccdf72a6566ef4d0bfb9b402e5e8e9538f7f004c23ae88edd4f11f
hash=0fed4478ce6af79b8bbf0755fda9d7112922577bedacdaccf6060ba8da236f46

8a627ea4f4de5b2578d83c9c2bbee497dd8db8f8e0e0b4af0c8e42b485ca5390
c=test.proxy
tset l2amc.proxy test.proxy 
tpush $c test '[ "0246adbdc438ccdf72a6566ef4d0bfb9b402e5e8e9538f7f004c23ae88edd4f11f","SIG_K1_KYzv7ZYNnXwMwF1qZLivS1swFbLfuh7rz5fwcpu9Dft8miAREDCPnw6keQs1FjPjxLsqdmYj8qKnuv8Ue7KmwxAG4ssFGv"]' -pad

tpush $c test '[ "0246adbdc438ccdf72a6566ef4d0bfb9b402e5e8e9538f7f004c23ae88edd4f11f","SIG_K1_KYzv7ZYNnXwMwF1qZLivS1swFbLfuh7rz5fwcpu9Dft8miAREDCPnw6keQs1FjPjxLsqdmYj8qKnuv8Ue7KmwxAG4ssFGv"]' -pad


mset l2amc.owner l2amc.owner
mset btc.proxy l2amc.proxy


mpush l2amc.owner init '[ad,btc.proxy,"0.10000000 AMAX","0.10000000 AMAX"]' -pl2amc.owner
mpush btc.proxy init '[ad,l2amc.owner]' -pbtc.proxy
mpush amax.token transfer '[ad,l2amc.owner,"10.00000000 AMAX",""]' -pad

temp_public_key = "AM5a3sXQaZqV6p88dCEN18GPGu8qRdyWgzo2zag9zmQCDYwjzrra"
temp_private_key = "5KfspX5UoJ8suxwQL5K8C57gdoqsCTc85jEbxjtrsFgpJJntDZV"

# btc 公钥绑定临时账号
# 1. 使用unisat对绑定用明文字符串“Armonia”进行签名
# 2. btc 签名格式转amax格式
# 3. btc 地址上余额大于0.1个btc可有提交到中心化接口


mpush btc.proxy activate '[btctest11111,"0246adbdc438ccdf72a6566ef4d0bfb9b402e5e8e9538f7f004c23ae88edd4f11f","SIG_K1_KYzv7ZYNnXwMwF1qZLivS1swFbLfuh7rz5fwcpu9Dft8miAREDCPnw6keQs1FjPjxLsqdmYj8qKnuv8Ue7KmwxAG4ssFGv","AM5a3sXQaZqV6p88dCEN18GPGu8qRdyWgzo2zag9zmQCDYwjzrra"]' -pad


mpush amax.token transfer '[ad,btctest11111,"10.00000000 AMAX",""]' -pad

# 交易打包签名
# 1. 交易打包

# code：合约托管账号名称，字符串
# action：要调用的合约动作名称，字符串
# args：合约动作参数，JSON对象

curl -X POST --url http://t1.nchain.me:18887/v1/chain/abi_json_to_bin -d '{
  "code": "amax.token", 
  "action":"transfer",
  "args": {"from":"btctest11111","to":"ad","quantity":"1.00000000 AMAX","memo":""}
}'
# 返回结果
{
  "binargs": "104208216395513e000000000000403200e1f5050000000008414d415800000000",
  "required_scope": [],
  "required_auth": []
}

# 2. 获取btc公钥对应临时账号next_nonce（中心化接口获取或读取合约l2amc.owner l2amcaccts.next_nonce）再次打包
curl -X POST --url http://t1.nchain.me:18887/v1/chain/abi_json_to_bin -d '{
  "code": "btc.proxy", 
  "action":"proxyaction",
  "args": {   
             "actions":[{
                "account":"amax.token",
                "name":"transfer",
                "data":"104208216395513e000000000000403200e1f5050000000008414d415800000000"            
            }],
            "nonce":"2"
        }
}'

# 3.将返回结果中binargs 进行unisat签名转amax格式
# 4. 使用账号的sumitperm 权限调用proxy合约
mpush btc.proxy submitaction [btctest11111,"0100c0549066d08d34000000572d3ccdcd21104208216395513e000000000000403200e1f5050000000008414d4158000000000131","SIG_K1_KDoDkyfWptZFmzN9K565iYfadeLoAPgYdUKTbGpQda9c3wqoyJojY5Z1MXUibn5r33t7HoV6EmBFcVdjEPwUpTcZXURQhM"] -pbtctest11111@submitperm
mpush btc.proxy submitaction [btctest11111,"0100c0549066d08d34000000572d3ccdcd21104208216395513e000000000000403200e1f5050000000008414d4158000000000132","SIG_K1_KX7QwVEzpck9g1juFLgNWVYpZDNRELgYALRTxiy7tjgqPJnwhXYzdGastcvwbLoxwUx7Y8sEQRX3yzr4ycGKK7jbR8sdo1"] -pbtctest11111@submitperm


