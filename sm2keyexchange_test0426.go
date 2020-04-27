package main

import
(
	"fmt"
	"crypto/rand"
	"gm/sm2"	
)

func main(){

	const (
		KeyBits = 128
	)

	var (
	initiatorId =[]byte(nil)
	 responderId =[]byte(nil)
	)
	// 发起人A生成sm2私钥dA和公钥PA，PA公开
        initiatorStaticPriv, initiatorStaticPub, _ := sm2.GenerateKey(rand.Reader)
	// 发起人A生成临时私钥rA和临时公钥RA，RA发给响应人B
	initiatorEphemeralPriv, initiatorEphemeralPub, _ := sm2.GenerateKey(rand.Reader)
	// 响应人B生成SM2私钥dB和公钥PB，PB公开
	responderStaticPriv, responderStaticPub, _ := sm2.GenerateKey(rand.Reader)
	// 响应人B生成临时私钥rB和临时公钥RB，RB发给发起人A
	responderEphemeralPriv, responderEphemeralPub, _ := sm2.GenerateKey(rand.Reader)
    

        fmt.Println("initiatorStaticPriv:\n", initiatorStaticPriv.D)
        fmt.Println("initiatorStaticPub x:\n", initiatorStaticPub.X," initiatorStaticPub y:\n",initiatorStaticPub.Y)
        fmt.Println("initiatorEphemeralPriv:\n", initiatorEphemeralPriv.D)
        fmt.Println("initiatorEphemeralPub x:\n", initiatorEphemeralPub.X," initiatorEphemeralPub y:\n",initiatorEphemeralPub.Y)
	fmt.Println("initiatorEphemeralPub Curve:\n", initiatorEphemeralPub.Curve,"\n")//判度RA是否符合曲线
	
	fmt.Println("responderStaticPriv:\n", responderStaticPriv.D)
        fmt.Println("responderStaticPub x:\n", responderStaticPub.X,"responderStaticPub y:\n",responderStaticPub.Y)
	fmt.Println("responderEphemeralPriv:\n", responderEphemeralPriv.D)
        fmt.Println("responderEphemeralPub x:\n", responderEphemeralPub.X," responderEphemeralPub y:\n",responderEphemeralPub.Y)
	fmt.Println("responderEphemeralPub Curve:\n", responderEphemeralPub.Curve,"\n")//判断RB是否符合曲线


	//响应人B接受发起人A的RA，生成共享密钥KB和证明SB\responderResult.S1、S2\responderResult.S2，将SB发给发起人A
	responderResult, err := sm2.CalculateKeyWithConfirmation(false, KeyBits, nil,
		responderStaticPriv, responderEphemeralPriv, responderId,
		initiatorStaticPub, initiatorEphemeralPub, initiatorId)	
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//发起人A接收响应人B的RB和SB，生成共享密钥KA和证明SA\initiatorResult.S2，将SA发给响应人B，并判断S1\s1=SB\responderResult.S1
        initiatorResult, err := sm2.CalculateKeyWithConfirmation(true, KeyBits,responderResult.S1,
		initiatorStaticPriv, initiatorEphemeralPriv, initiatorId,
		responderStaticPub, responderEphemeralPub, responderId)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	 fmt.Println("initiator's ShareKEY:\n",initiatorResult.Key)
        //响应人B接收发起人A的SA，并判断S2\responderS2=SA\initiatorS2
	if !sm2.ResponderConfirm(responderResult.S2, initiatorResult.S2) {
		fmt.Println("responder confirm s2 failed")
		return
	}
        fmt.Println("Responder's ShareKEY:\n",responderResult.Key) 
	fmt.Println("S1=SB:\n",responderResult.S1)
	fmt.Println("S2=SA:\n",responderResult.S2)  
}
