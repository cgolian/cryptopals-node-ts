import {CryptoBigNumber, sha1} from "../set5/utils";
import {DSAParams} from "./challenge43";
import {DSASignedMessage, DSASignedMessagePair, recoverDSAPrivateKeyFromRepeatedNonce} from "./challenge44";

describe('Challenge 44', () => {
    describe('DSA repeated nonce', () => {
        let dsaParams: DSAParams;
        let messages: DSASignedMessage[];

        beforeEach(() => {
            dsaParams = {
                p: new CryptoBigNumber('0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578' +
                    'b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fd' +
                    'a812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1', 16),
                q: new CryptoBigNumber('0xf4f47f05794b256174bba6e9b396a7707e563c5b', 16),
                g: new CryptoBigNumber('0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db6' +
                    '20c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556' +
                    'fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291', 16)
            };

            messages = [
                {
                    msg: Buffer.from('Listen for me, you better listen for me now. '),
                    s: new CryptoBigNumber('1267396447369736888040262262183731677867615804316', 10),
                    r: new CryptoBigNumber('1105520928110492191417703162650245113664610474875', 10),
                    m: Buffer.from('a4db3de27e2db3e5ef085ced2bced91b82e0df19', 'hex')
                },
                {
                    msg: Buffer.from('Listen for me, you better listen for me now. '),
                    s: new CryptoBigNumber('29097472083055673620219739525237952924429516683', 10),
                    r: new CryptoBigNumber('51241962016175933742870323080382366896234169532', 10),
                    m: Buffer.from('a4db3de27e2db3e5ef085ced2bced91b82e0df19', 'hex'),
                },
                {
                    msg: Buffer.from("When me rockin' the microphone me rock on steady, "),
                    s: new CryptoBigNumber('277954141006005142760672187124679727147013405915', 10),
                    r: new CryptoBigNumber('228998983350752111397582948403934722619745721541', 10),
                    m: Buffer.from('21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4', 'hex')
                },
                {
                    msg: Buffer.from('Yes a Daddy me Snow me are de article dan. '),
                    s: new CryptoBigNumber('1013310051748123261520038320957902085950122277350', 10),
                    r: new CryptoBigNumber('1099349585689717635654222811555852075108857446485', 10),
                    m: Buffer.from('1d7aaaa05d2dee2f7dabdc6fa70b6ddab9c051c5', 'hex')
                },
                {
                    msg: Buffer.from("But in a in an' a out de dance em "),
                    s: new CryptoBigNumber('203941148183364719753516612269608665183595279549', 10),
                    r: new CryptoBigNumber('425320991325990345751346113277224109611205133736', 10),
                    m: Buffer.from('6bc188db6e9e6c7d796f7fdd7fa411776d7a9ff', 'hex')
                },
                {
                    msg: Buffer.from('Aye say where you come from a, '),
                    s: new CryptoBigNumber('502033987625712840101435170279955665681605114553', 10),
                    r: new CryptoBigNumber('486260321619055468276539425880393574698069264007', 10),
                    m: Buffer.from('5ff4d4e8be2f8aae8a5bfaabf7408bd7628f43c9', 'hex')
                },
                {
                    msg: Buffer.from('People em say ya come from Jamaica, '),
                    s: new CryptoBigNumber('1133410958677785175751131958546453870649059955513', 10),
                    r: new CryptoBigNumber('537050122560927032962561247064393639163940220795', 10),
                    m: Buffer.from('7d9abd18bbecdaa93650ecc4da1b9fcae911412', 'hex')
                },
                {
                    msg: Buffer.from("But me born an' raised in the ghetto that I want yas to know, "),
                    s: new CryptoBigNumber('559339368782867010304266546527989050544914568162', 10),
                    r: new CryptoBigNumber('826843595826780327326695197394862356805575316699', 10),
                    m: Buffer.from('88b9e184393408b133efef59fcef85576d69e249', 'hex')
                },
                {
                    msg: Buffer.from('Pure black people mon is all I mon know. '),
                    s: new CryptoBigNumber('1021643638653719618255840562522049391608552714967', 10),
                    r: new CryptoBigNumber('1105520928110492191417703162650245113664610474875', 10),
                    m: Buffer.from('d22804c4899b522b23eda34d2137cd8cc22b9ce8', 'hex'),
                },
                {
                    msg: Buffer.from("Yeah me shoes a an tear up an' now me toes is a show a "),
                    s: new CryptoBigNumber('506591325247687166499867321330657300306462367256', 10),
                    r: new CryptoBigNumber('51241962016175933742870323080382366896234169532', 10),
                    m: Buffer.from('bc7ec371d951977cba10381da08fe934dea80314', 'hex')

                },
                {
                    msg: Buffer.from('Where me a born in are de one Toronto, so '),
                    s: new CryptoBigNumber('458429062067186207052865988429747640462282138703', 10),
                    r: new CryptoBigNumber('228998983350752111397582948403934722619745721541', 10),
                    m: Buffer.from('d6340bfcda59b6b75b59ca634813d572de800e8f', 'hex')
                }
            ];
        });

        it('should recover private key from message signed with an already used ephemeral private key', () => {
            const expected = Buffer.from('ca8f6f7c66fa362d40760d135b763eb8527d3d52', 'hex');
            const repeatedKMap: { [key: string]: DSASignedMessage[]} = {};
            // find messages signed with the same ephemeral private key
            messages.forEach((message) => {
                const rStr = message.r.toString(16);
                if (repeatedKMap[rStr]) {
                    repeatedKMap[rStr].push(message);
                } else {
                    repeatedKMap[rStr] = [message];
                }
            });
            Object.keys(repeatedKMap).forEach((r) => {
                const msgs = repeatedKMap[r];
                if (msgs.length >= 2) {
                    const msgPair: DSASignedMessagePair = {
                        signedMsg1: msgs[0],
                        signedMsg2: msgs[1]
                    };
                    const privateKey = recoverDSAPrivateKeyFromRepeatedNonce(msgPair, dsaParams);
                    const privateKeyDigest = sha1(privateKey.toString(16));
                    expect(expected).toEqual(privateKeyDigest);
                }
            });

        });
    });
});