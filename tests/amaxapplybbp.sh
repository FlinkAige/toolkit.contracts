con_bbp=bbptest12
tnew $con_bbp
tset $con_bbp amaxapplybbp

tcli set account permission $con_bbp active --add-code

con_bps=amaxapplybps
tnew $con_bps
tset $con_bps amaxapplybps
tcli set account permission $con_bps active --add-code

bbpadmin=bbpadmin
mpkey=AM7n5TBaSnZLkrn8yYk54YveYoyQujJaMGK546gPze1Vy5MsM3S6
# tnew bbpadmin
tpush $con_bbp init '["'$bbpadmin'","'$mpkey'","'$con_bps'"]' -p $con_bbp
tpush $con_bps init '["'$bbpadmin'","'$con_bbp'",1300]' -p $con_bps
tcli get table $con_bbp $con_bbp "global"
tcli get table $con_bps $con_bps "global"


bbp_owner1=bbp.owner123
tnew $bbp_owner1

bbp_owner2=bbp.owner22
tnew $bbp_owner2

plan_id=1
bbp_quota=1
tpush $con_bbp setplan '["'$plan_id'","'$bbp_quota'",2, [[["8,AMAX", "amax.token"],"1.00000000 AMAX"], [["6,MUSDT", "amax.mtoken"], "0.000000 MUSDT"]], []]' -p $con_bbp
tcli get table $con_bbp $con_bbp "plans"

tcli get table amax.ntoken ad "accounts"
plan_id=2
bbp_quota=30
tpush $con_bbp setplan '["'$plan_id'","'$bbp_quota'", 2, [[["8,AMAX","amax.token"],"2.00000000 AMAX"]],[[[[1001,0],"amax.ntoken"],[1,[1001,0]]]]]' -p $con_bbp



tnew bbpvote112
tnew bbpvote212
tnew bbpvote312

tnew bbpvote113
tnew bbpvote213
tnew bbpvote313
tnew bbpvote114
tnew bbpvote214
tnew bbpvote314

tpush $con_bbp addvoters '[["bbpvote112","bbpvote212","bbpvote312","bbpvote113","bbpvote213","bbpvote313"]]' -p $con_bbp
tcli get table $con_bbp $con_bbp "voters"
tcli get table $con_bbp $con_bbp "plans"


tcli get table $con_bbp $con_bbp "global"

tpush $con_bbp applybbp '["'$bbp_owner1'",1,"logo_uri","org_name", "org_info","mail","manifesto","url",1232, null]' -p $bbp_owner1
tcli get table $con_bbp $con_bbp "bbps"

tpush $con_bbp applybbp '["'$bbp_owner2'",2,"logo_uri","org_name", "org_info","mail","manifesto","url",1232, null]' -p $bbp_owner2

tcli push action amax.token  transfer '["amax", "'$bbp_owner1'", "10.00000000 AMAX", ""]' -p amax

bbp_owner1=bbp.owner123
tcli push action amax.mtoken  transfer '["ad", "'$bbp_owner1'", "10.000000 MUSDT", ""]' -p ad


tcli push action amax.token  transfer '["'$bbp_owner1'", "'$con_bbp'", "2.00001000 AMAX", ""]' -p $bbp_owner1
tcli push action amax.mtoken  transfer '["'$bbp_owner1'", "'$con_bbp'", "1.000010 MUSDT", ""]' -p $bbp_owner1

tcli get table $con_bbp $con_bbp "bbps"

tcli push action  $con_bbp tsetvoteridx '[18]' -p $con_bbp

tpush amax.ntoken transfer '{"from": "'$bbp_owner2'", "to": "'$con_bbp'", "assets": [[1, [1001, 0]]], "memo": ""}' --permission $bbp_owner2@active

tnew bbpvote112
tnew bbpvote212
tnew bbpvote312

voter=bbpvote312
tpush amax updateauth '{"account":"'$voter'","permission":"active","parent":"owner","auth":{"threshold":1,"keys":[],"waits":[],"accounts":[{"weight":1,"permission":{"actor":"'$con_bbp'","permission":"active"}}]}}' -p $voter