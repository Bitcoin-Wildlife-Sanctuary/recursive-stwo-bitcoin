./bitcoin-cli --datadir=signet sendtoaddress tb1q63ntetcznnpx2hgv3eaduhq4ughspu5cuj7m8d 0.0192
b2ee8ac5651cc8b7c6db08dde0c91ef50efa064814198155bee6f70db6bc089b

./bitcoin-cli --datadir=signet createrawtransaction "[{\"txid\":\"b2ee8ac5651cc8b7c6db08dde0c91ef50efa064814198155bee6f70db6bc089b\", \"vout\": 0}]" "[{\"tb1p3703yr97urstm70qtztl29mljg28jxeeyfmk4tpe0t8987x84nvqyr8k4f\":0.01919270}, {\"tb1qyxj2y3dhuvyh8rv6lhkk0q4e0990xt489fdp2c04pmkqlv49rdwq3djtvc\":0.0000033}]"
02000000019b08bcb60df7e6be558119144806fa0ef51ec9e0dd08dbc6b7c81c65c58aeeb20000000000fdffffff0226491d00000000002251208f9f120cbee0e0bdf9e05897f5177f9214791b3922776aac397ace53f8c7acd84a0100000000000022002021a4a245b7e309738d9afded6782b9794af32ea72a5a1561f50eec0fb2a51b5c00000000

./bitcoin-cli --datadir=signet signrawtransactionwithwallet 02000000019b08bcb60df7e6be558119144806fa0ef51ec9e0dd08dbc6b7c81c65c58aeeb20000000000fdffffff0226491d00000000002251208f9f120cbee0e0bdf9e05897f5177f9214791b3922776aac397ace53f8c7acd84a0100000000000022002021a4a245b7e309738d9afded6782b9794af32ea72a5a1561f50eec0fb2a51b5c00000000
{
"hex": "020000000001019b08bcb60df7e6be558119144806fa0ef51ec9e0dd08dbc6b7c81c65c58aeeb20000000000fdffffff0226491d00000000002251208f9f120cbee0e0bdf9e05897f5177f9214791b3922776aac397ace53f8c7acd84a0100000000000022002021a4a245b7e309738d9afded6782b9794af32ea72a5a1561f50eec0fb2a51b5c0247304402203899443340eccbd30e88fc658e6ba3768a5593dd3ba530c9486ccaaa55dfcdba022008ab0ca60b926126c3b16d989ffcaacbf8528dcd3490c91a0eec60ca8f9823bc012103b115d4031d72ace1a4efd3a1568b4ee02fa7739e470e2c086648be5a36ac4d2a00000000",
"complete": true
}

./bitcoin-cli --datadir=signet sendrawtransaction 020000000001019b08bcb60df7e6be558119144806fa0ef51ec9e0dd08dbc6b7c81c65c58aeeb20000000000fdffffff0226491d00000000002251208f9f120cbee0e0bdf9e05897f5177f9214791b3922776aac397ace53f8c7acd84a0100000000000022002021a4a245b7e309738d9afded6782b9794af32ea72a5a1561f50eec0fb2a51b5c0247304402203899443340eccbd30e88fc658e6ba3768a5593dd3ba530c9486ccaaa55dfcdba022008ab0ca60b926126c3b16d989ffcaacbf8528dcd3490c91a0eec60ca8f9823bc012103b115d4031d72ace1a4efd3a1568b4ee02fa7739e470e2c086648be5a36ac4d2a00000000
baf5d6243d16c20e6f8ddf427a3e364182bbb37f3fb23bcaafb38e5a59dd5d4e

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/1.txt)
e5e348c7f6e189c087fd2a48816577df5668b373ea05a3b33cf60344d7b0708b
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/2.txt)
b9eabd942ff5a7ffe6c4ec8d415e3a9371233697cf14a8348aadd4fcbdbf093e
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/3.txt)
02de8bd26dd9909855b459e388b478c56220b6e9181ce62f92b7952968bda2d1
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/4.txt)
fe07771a93f53168591c109fcc67928cd45e826a8eca268acfcbdcd5c9e36cbb
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/5.txt)
29e3a8cccffeb6f037094ae668a12de8ea88df455c46fe67e15524bd32e4faad
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/6.txt)
86e82b26a6273b0336ee0b7692bf1f1817853121133c11888ba5a96d13603b62

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/7.txt)
9386157e91c66475d240deedb988408024b7ca67fc05519d6c9f03fda9cf951a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/8.txt)
c26c82a9d3c0f2a563bbd2655eb6ef828a6b301d65a2dbb38bc4e810db139308
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/9.txt)
8359064315c91c6be35f445d4976070ef33fb82ff7c1c79a5fba4a1c14caa8a7

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/10.txt)
180332a39f22d4999478f70bbf3fca4590a0a9f63f4e6570ebb62f83da543923
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/11.txt)
cf5c8fa013155996100eea5bb9cf904d8e4b4b539ba03f726a9ddfc59af84f6d
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/12.txt)
cba623b5e75628f6fa48f5471be084394a4462828bdb5649355498fa19680bc0
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/13.txt)
905a850905db6e3cf4ec2a880bb13020302d5fcc0904a8f3327cf1c3c40d6056

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/14.txt)
8c445a89374e244af5869a9fa8776bac3bf30efb914dd18999a90dbd7674d785
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/15.txt)
7007c698acaa90ad168822fae89b17a135870da43c5700da3d16ac58b5ed29b5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/16.txt)
7402bcd73f4639bcfaa6021539738e261fc293033c837d46ca6411f512efb576

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/17.txt)
8e6607340e7d8c51636dd7195cdd5399133838aadcdf93d14ec15e153562d7e0
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/18.txt)
ed1d3e4b836eee25a074e71bc4373ebf57afb0bb16a399fd953c0e6ba6c0b603
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/19.txt)
cb95580abb8cf478cdd24e0de21ce495645fe45638e2a52ed1187790ca3feed3
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/20.txt)
6b2de5074fa68eecd13f2b47fb0891da6bde1b55accdee87d28f42191db76042

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/21.txt)
ccbced938d406fa0f47522bf42e9b1f55aa310e7417d4b4c4c7f9a4e0eebc624
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/22.txt)
1a4a4f1743fd0f3b1cb0d83b8bb44af61ba1eacb66cce804c73053fc3e8b27bb
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/23.txt)
f21ea0892557b1f5ee871765ca5e7bac886664e07a8614d4315b19542ad582b5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/24.txt)
5e914c8cb50e0f470a2ad62ed5a54c5cdf5db47548567d9aec7cb2783853c707
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/25.txt)
8e8b3e5df55a675afe4b73850e05d84725174e1ee145b68ba41736f9097b059a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/26.txt)
a9f13e8ff14d7b820aaca16bdf7bf18d5cd6a907e970722bdb35b3fed10e0d0b
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/27.txt)
2557334c00affe5c7473de3435fb6a4ff3578ae54f66e4ab8ce5cc324459b1d6

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/28.txt)
b9ae71a47e9be00ce6bb7dc1194ae57e1a74eaff0ca40f54915ae462ff343cbc
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/29.txt)
0392cd62169d21eafb039acf40f1acb4d00ca125ac05b50787cd1c886a8a263a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/30.txt)
744aca9aa0354556a641a706d9d78a1399e37d4a8ceb9eed753d5d3be01c78d5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/31.txt)
baaff027ef093cf991080af71ce9d21ab6f4136e4984f2ad897d4c9de9e59377
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/32.txt)
172af7d4cbb48dcc7e5f82c2a1e6673a518548f52b5a4ee75d92b4cc08790971
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/33.txt)
050dc31c810dd067d5d645ea84fa1c23afa4934b590316189a1353932db3adce
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/34.txt)
cdd53d1d7794fbc5da70080aafb296f8a09d24aefb725837939d52a0348ff87d

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/35.txt)
ccee05b1ed62a5bd4a55396c4c8f474959c609141ede0bc052d20c7257fa71c5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/36.txt)
015e51944ef3d625f149f0bba663bbb13f881835f6d7ae7f3eb2fd0a9f7e7abe
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/37.txt)
f20d270a8442da40c0944a4b9fc7074a8802ffdb9612f4f3f823ac947b41564d
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/38.txt)
63d8027e104d19112a20ac9858d0c475a0c651e773472c78a988178ba0170108
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/39.txt)
96d09669092d00bd61dd8420e93c9a72a1846e4e931be63a0ae831316d5db962
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/40.txt)
6123a9a394acd908ffd2eff459189486a96056baf19f0213812ecedebc5c344a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/41.txt)
a12de5a4deee8044de746a3300530618bf07f0d8848a1a78309535b75a32504d

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/42.txt)
06c09b47ee7273d777df5c0df218ae20b086b40cef251f71beb60bb8a3457a3b
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/43.txt)
7f4b546116f7cee408885527e4af764d3df12d092cec8bdb4b45daa114f1f91a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/44.txt)
352a5ca6a3138ab1bdfe7a7437c913f8402a8da6e0a27763f89d0468f3e9b186
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/45.txt)
1b85803c567f924a6e318d739bea9647a71a8bd17a594ed8ca1b0f15467fd2b4

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/46.txt)
780812413de7dc50c2db5f98b0bd4e6e09e3aa7aa8e7210ff455e841da85c76d
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/47.txt)
3b74f1d3662d70a0584a5075bf3c9113a0616d0fadd6c772199fb171082ef690
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/48.txt)
6cb6ebdb172e2a82ec9bd50977b8fcddd8504bd5afe11925265e4c0e55a58e2a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/49.txt)
9e0e4037cd56be271716636a18f05e0140309938dbe43e435a72d36da1fdf93d
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/50.txt)
36f5cd617ef58127f2b1fb9df2c6aa87ce86d398e8d05b7a9ff6fc4df2caaca0
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/51.txt)
2e0af3a85c75e258503ea5b810d1b49622494dba83fd4877d7002a3f337e2ce2
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/52.txt)
08f61029c6dffa5ab72e6bbc2c8192c996070f54db356f5fc67e36bcdcca1dd7

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/53.txt)
a539f8f645353e14a4bc2bf996ab349444e8dbcb5c05a45fb675360ad8464e64
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/54.txt)
1bc54e762d3fb036fd6e0e354e809aea43741e8fe080bed4c5b379f3dc8d308e
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/55.txt)
00ab82a823d2904a9f655d669d3e0eb1b7a4f85507bba8febb23e9490bda207c
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/56.txt)
ab0cc3c21bb43473321f2da2307b968c2aedf7b05cf5c82c0b9c25e04ede78b6
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/57.txt)
d498567d3ad7772c60875db0339e1e333a07e8c408853880cf8585e76ec5cf29
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/58.txt)
abb07700e2950d469cd4b88f42feaae41daaa3808a4d0870ce15e116ac23fbf6
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/59.txt)
b6de725321a8d076ebccb1591d99b50b3e28d477ff1de21e504b99d03f85d15a

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/60.txt)
982395f2a1969d6c2cb19e401845e1986b5f9dd691aafea8b6aec8771703406c
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/61.txt)
1b698971db0c26a40781f91567afcc4e45df188d6fba82e05149c5480197f427
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/62.txt)
7f4d438f956588012f13d16207552ee07d9a858f9319d00bfd85bce669653621
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/63.txt)
a52f6b26182dc1506973da70985622a8982ae4f54cbe0d12f24fee659666f4b5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/64.txt)
83ad52a38d2518bace28e1a0a953f6dd5c97dfec62c92bc48f8aee9d89a9b605
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/65.txt)
c639fd89aaa3d58ccd94c203c08cf6c7a436266dd44006c9902a9e095ff0a15c
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/66.txt)
237ff51e9070c715f88385f6b33e6661756a6556a53f231e97858db4e4323363
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/67.txt)
80bb4dc38cc36778905e0851adef739677c9ec1c7634f44071da9ae05ab9ddf7
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/68.txt)
e50f4265d4ab3a39367d822d1488779e1126430f839ee6b654abdb5648867866
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/69.txt)
8a884905acebd4ad25c80279e42b27c9875f42999c8609ef74b94f1772aff0ab
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/70.txt)
2f660958109791537bfe52b02711cb31b7f82481c2a9c901d825a7d89a71382a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/71.txt)
1b98253ee7572c63af1b9255b445a4d712146897aba2f7eb15613e080da32dda
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/72.txt)
614e5365e7a2d95d0151ccae61e09c7918b3216f34966e835e9aaac88994d2bd
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/73.txt)
89c5ca681cfa993caa9ba91c953e5a38b5f2154b99b62b171352a806d9b3a141
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/74.txt)
43522907cd082227e1ae7d86c65c77d453545d9991953db2ca9710eb550e934e
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/75.txt)
387dee8c3e7ddd914ad3c39f4fb2cb7509c0984697c27b0d6d4c86c80c223b53
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/76.txt)
2be193f759cd700c08050e77854854c1f9a64592e1720a87873d153a5cb20e7a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/77.txt)
64e714309f8916c2202098392f7b3534d061424d052ef0d4bf4fd88ebe80bd19
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/78.txt)
e001bcb3875cae4abf3c770bcb3644f83b37bfc73c1078f11648fa65f11c1a12
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/79.txt)
9c5973b6dafa0f28609a7ccef23bda2150b6f1a7ccc515310ae0be1e83e30cc9
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/80.txt)
ee4d859af56951c1a0297d6fdf9ef051d84531d360b9fd1865ee6ac56a5a13d2
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/81.txt)
d777fe9688f3facec4a6ea60047f3bc867d5b810797e1d81b91c7acbebe3d932
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/82.txt)
41cc19fb24d834d46891722a6e634bb9d094bb2094a7e6b8997f2dc229124956
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/83.txt)
93994120e039f67e886238aef62edef56e9a1a444095422e1271270711d4980f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/84.txt)
923809ced187f9f509024fe5d872c7bab1cb2d7f9c556c06c264695b1455a770
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/85.txt)
df90fcf08f41a2e4c6b054a04c413fcdd42fe7bf342d56fe8dc5a3010b5623b0
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/86.txt)
7abbc3e3e2c3dd2b914d4eba5a6ec505f0012118c02d0c5ace9fa047750b9299
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/87.txt)
8c1152980bf4134e41dafcbd979988db9aa29e9a4e1e4d410e5d2030fee13d9f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/88.txt)
b7af18fc6a00603c601ab9a4f99fd1a80d611118e0b32fbe71084b998dd4b208
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/89.txt)
c315c8700a5f598d023907a2d2837e95e845b3c0d6327e7a0f2fc079debc0725
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/90.txt)
d932f20def8abcb4838ea9fa166cdb3c565be307f6f2e40cd9f35362fe01e8d7
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/91.txt)
076c8ff866f71629942eb31e12fd51cc01dcb9302c9e9cafb12106c12710933c
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/92.txt)
22656940638d5528faad85131716b334b5a95a7414a8845f138f11a89098242f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/93.txt)
146b0d9c807419cc7b7020a7649b0bd8ac77f8b383fb91655095cd35bb011175
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/94.txt)
a46c262b469e903b4583a265905ed3c6896b82cbb30b101cc9fdd9ca732dc341

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/95.txt)
9210cdc2b2801be9d0fb7fc664cc641b7ec77aa238a61abe6d9cbbfddea8c4c3
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/96.txt)
42523a615be480335dd6f553114af9acc185966a060bb72406dcb89d417f4d46
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/97.txt)
0a7c533905b91db3aad95feff2efe175db9e518858eb56418215b9030887d9b4
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/98.txt)
5fcf8af6f2054a69005423ce3c6ce7fc697070eade2108012d9d851b969c9f74
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/99.txt)
5dd658b0727087df0a6003b4c87868cf89a1599406619e24ca39d19555a4ab42
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/100.txt)
2b4e59efbe87b67ab6fc38ff247585741d2dff29e86ecde1b422617268a1ecd3
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/101.txt)
32c27d4487ad612a64b7b66622add6594a9f93880d91d87700395bc5147912db

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/102.txt)
60a2fab7b63eb923527b5081d9a13e6a761aa5568a3352082fb19242b276e5b0
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/103.txt)
1c1acfd76435f22cb12f1e08a2a81def2ee504523c0720cf2bc54574aaef907f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/104.txt)
629a63598774edf8403b1081fbb601f5d16e7bfd118513f1fc6ba46bceb81975
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/105.txt)
e40cc65548f45d661116fdc35e7df2a1f86744b5fd8ff99b06b40bbe3fcbf537
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/106.txt)
eb2e9a97de233434e772915b5604f28aec229d06cef93bbc6b2f16b6b727c249
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/107.txt)
b55746322d726f62c22ca64d85b98fcbb82aaed6f41ed8a59d36b55a35d7933b
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/108.txt)
9a5199026e9d6cf6bf8e198683c5a34a443fcb1e7ff019c8bb3029174c249246
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/109.txt)
5222b629b90f8c3fe152517c5cdc61af2697d3bc72e5f5760807aa2314967d20
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/110.txt)
26aac0eb266b290b045bd542186797f9a539c634b445e6f756e8e1cc38ea68c9
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/111.txt)
369677b2afef9fce634f9da170072354e654e0f55f26f09a873bc826fc58e6f0
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/112.txt)
f4aab60c90dcb8753dd484422105b66c1276394a9f8099e250afe3468994f725
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/113.txt)
a9bc129e1e827e86841456ba666d7d606a8a1b8a06e3856082e69f1727db4c81
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/114.txt)
68747feb7d5fa5d215dc8685f702997f8fb310c8e24e4e73f27f806b7c7b5c40
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/115.txt)
6015ec31f2b34aa4c1beca97626f9ec3840daefc1e6bf8b6fe9f747c40674ff0
/Users/cusgadmin/go/bin/stakercli --help
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/116.txt)
6bfb7ac3fb9d6c4915c75b155e166a48c625986f720ba2cba8d537fb8c940df5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/117.txt)
d9cf252b0e0ac3a18affaeffa7a6b0f240a09f24de740479fb4d38df62adf50e
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/118.txt)
4f8def63a36299147037667d2fd7bdc16094261cd57e8f669bf27af71083f5f8
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/119.txt)
05563083c2b8bf95fae124197be4c4463d3008cfe70e1e5e9afc11c347d10605
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/120.txt)
3245b42e5b3b7837f57dbc642fd97bd6eeb6fa9a2d1f438b52c51a14fa32b5b8
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/121.txt)
e0aba9e0f2c5240977398c4397be6162e34a179ae6ee625ebb6b0ad555df1668
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/122.txt)
b4b53534b6db694623479d36d476453e10fd7a4dad8c425ee831abc0e79a7a62
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/123.txt)
0fd8722abe8cb737af674c7a31ac1a0ffb40cefbd09d91be7acba3e7a309bf87
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/124.txt)
228fac099608f34f2517ef415bc387afd6413fd0a6b6d09b8919bc9d107c9c04
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/125.txt)
acbeb42895765837efd95f6faf154a76dde0f0b272c7ab8a30e0c5057964a7f8

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/126.txt)
570d8320501172eb0633eec295d3cec94931834d7c5edfed6081d98cfb236832
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/127.txt)
e3d67644afea47a06a204667cea7efde4f8f58eebca1f2d9396db76b23414547
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/128.txt)
d1926807ed5511f03804b86b3d5f52f6c2da4c96b6dc56e38b5cba2fdf43351f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/129.txt)
18399cd1778220ab43a64fa657f72f29697f09bf6d0b70ed9bd9eeeb5f505032
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/130.txt)
25cc2717f004364fcdac0728a512ac9d3d9b5a1bbeac690d008cb58db7d29012
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/131.txt)
f2ca8bcbcefdd2dfaaed5b9b67688e4595979e8f1cf5d755b170fcab73874987
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/132.txt)
673111d53181d71c3adba468ead7cfb860d542ad400979222d7a3f526b22f246
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/133.txt)
161cd1d46e8e8ce52b8a6ba2e96b8cc4919cbd92e54b88c500bdcbc7d93db95d

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/134.txt)
c76eaab31f096dcad95f35ac07686d66635bca2da754f910413ac8f66a4f8a50
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/135.txt)
48af5bd73c23f235ffed594e9363ed2da7394cbc4e220cf5ef476a1522395174
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/136.txt)
746552302139cf88cf70658955c3924585f6f372356540232ae4e746b8456fbc
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/137.txt)
63634fb7cf0511aa157df0bac490771e68c3e4c2928a5a231b06bcc9ab8060ff
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/138.txt)
b7c0561afed7adf8b02a942c768ccdb8699f536ed66c3f5aa5947ab3eb8f31d9
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/139.txt)
86ffc81d26342cb85a212c43ce009d7f481d4b64f9dc318c80ba6fa300c74d9f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/140.txt)
f2c90e644a2f6c726c353b94f4d41f44a47cc7fdcdef14b2c70f41991ad0988d

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/141.txt)
1db1f0dd3baf0fa6bffa8405d773a0849e36afe58687f1a43ce31e56a9cde72a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/142.txt)
de663ef3b7482d0a9ba38d2968cd1630c286f0696dad2ecc5ea3f87c649974d8
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/143.txt)
9f64cde600bf6ac4ce567da497ee0cb212652a5a82176f7d1ea72af6f73a857a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/144.txt)
f53fab7b94970a5d51d707dbb74c1a37d12d4c7b20dc6a5260233b69cbdcf1af
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/145.txt)
e7afa55eae87b135ab7cb5c44aab1a1f74d2f85f0da81219cbcac98679313595
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/146.txt)
87c2fb96aa532368ed100f8b324e9fce2c28efc17e79b37e2fdeb87723a4444f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/147.txt)
cfc465ef67ec47d82348214e21867d5cfabc8e5a7dae80683b930ee59fa0ee5d

./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/148.txt)
e61330600d1ab3299f1886c346f9ee4c145820b0de724b927dd11a0fc72d4088
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/149.txt)
9e7bddaeb4f3443aaf0e29e87e28742266f309ea6e0615284bb83577cd526120
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/150.txt)
a78ecef98ca566e4e8cb1f662ea13e0ec1ea1d423a655867b6e072330c678cf5
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/151.txt)
9ec70b7574213dc99ee690c1e5a210cde8dbb7a14f992beeb9c3c782066e9fb3
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/152.txt)
8d8440923fd3866f261bd83e3455b2433839c0254ccba29b91f690d58b08d289
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/153.txt)
7d895febe773d9f0e40ca18f4e7ccc19c3dddfeafd7ccfdd1729193ea8eeee0d
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/154.txt)
13258722b2e261b654ba81e481e588eb2e51741edae1b688549fe8f600624fde
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/155.txt)
377c3708465232002a4ebe2ab98bc6a6b965605112dc9c1054bfe94d7c62922a
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/156.txt)
72831cba51fbe0feff2edd273dc1d02bdbbccc59c9779dbb576b2e364072cb0d
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/157.txt)
fd43cffed28447a093eb162b371939c1a954b4ee0b1a1208c5ede10a70225b0b
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/158.txt)
c10da81d917179145a6c4cbe359365ac595e944224c05360fe627209782db6aa
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/159.txt)
9dfdacb53fd2daa29d10895e10b87fceafb5029494e3dc08fc3047e2fa39f421
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/160.txt)
06e1f4ec943fc3cce12d7f8baf7e0adf0140ddca86ff6f62084a68f368f63871
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/161.txt)
00023fc0604496bb5e30a3f9101a267b205a41a39296351d115d5dd14423e7b7
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/162.txt)
54010f8aef99f94740d3a7905bc6c5fa83028eac3e6e1473bc69cb834eeb8dfc
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/163.txt)
b9e42961939890e52c102397abdbbb18b7411c581722646d90f553a46455f364
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/164.txt)
ee97148bedb968c083119c65863656853a3f259474fd72b0f71419d00105863e
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/165.txt)
588909ef2d28a2d7e81a3ad3acce2c91f7b49e0ad78f91d4b86509694a58b257
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/166.txt)
cf2418dfde278016459df2c19b92ef40360ebc249844333ce4a458a9e0272816
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/167.txt)
2e59b04ca52fd0cb3e5270babf3c2c205b697c9ca83e1038c97150cbd8b8d45c
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/168.txt)
297aa86fecbf344fd5a62663662cb941c10a7a8022cd7e83e42d81e0e6835f5f
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/169.txt)
0677ed461b474bce0424952c232050b3a24baa16d708262fb4a4c915e91a3cfd
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/170.txt)
14cb01d33e671da33bdc8c8747b7b7075b73fad1438fed9c34c8a471490e5056
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/171.txt)
7868032997c4c3d59c9a92eee2a9cc07cbf540cd138859bb59fab266b4b23725
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/172.txt)
0b7ce012403d75b3c948d0274d3ad10ad251d8f468c9166104d1931fd68f1365
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/173.txt)
6a4268c4601abd0a63694896d0ed5dfdc703d7bc7e88cc15e287f6dc69823831
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/174.txt)
e75c654c71e733b00469ac600c947c14d68b37077aa79b7996ee41ce9748e9da
./bitcoin-cli --datadir=signet sendrawtransaction $(cat ~/RustroverProjects/recursive-stwo-bitcoin/demo/175.txt)
ac64587f90486d5b55c615e58fa90b3a84d0f49f0184707c89173b3e3c9b4b6e
