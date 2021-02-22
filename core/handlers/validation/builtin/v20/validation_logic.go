/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package v20

import (
	"fmt"
	"crypto/sha256"
	//"math"
	"unsafe"
	"sort"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	commonerrors "github.com/hyperledger/fabric/common/errors"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/common/validation/statebased"
	vc "github.com/hyperledger/fabric/core/handlers/validation/api/capabilities"
	vi "github.com/hyperledger/fabric/core/handlers/validation/api/identities"
	vp "github.com/hyperledger/fabric/core/handlers/validation/api/policies"
	vs "github.com/hyperledger/fabric/core/handlers/validation/api/state"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"

)

var logger = flogging.MustGetLogger("vscc")

//go:generate mockery -dir . -name IdentityDeserializer -case underscore -output mocks/

// IdentityDeserializer is the local interface that used to generate mocks for foreign interface.
type IdentityDeserializer interface {
	vi.IdentityDeserializer
}

//go:generate mockery -dir . -name CollectionResources -case underscore -output mocks/

// CollectionResources is the local interface that used to generate mocks for foreign interface.
type CollectionResources interface {
	statebased.CollectionResources
}

//go:generate mockery -dir . -name StateBasedValidator -case underscore -output mocks/

// toApplicationPolicyTranslator implements statebased.PolicyTranslator
// by translating SignaturePolicyEnvelope policies into ApplicationPolicy
// ones; this is required because the 2.0 validator is supplied with a
// policy evaluator that can only understand ApplicationPolicy policies.
type toApplicationPolicyTranslator struct{}

func (n *toApplicationPolicyTranslator) Translate(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}

	spe := &common.SignaturePolicyEnvelope{}
	err := proto.Unmarshal(b, spe)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshal signature policy envelope")
	}

	return protoutil.MarshalOrPanic(&peer.ApplicationPolicy{
		Type: &peer.ApplicationPolicy_SignaturePolicy{
			SignaturePolicy: spe,
		},
	}), nil
}

// New creates a new instance of the default VSCC
// Typically this will only be invoked once per peer
func New(c vc.Capabilities, s vs.StateFetcher, d vi.IdentityDeserializer, pe vp.PolicyEvaluator, cor statebased.CollectionResources) *Validator {
	vpmgr := &statebased.KeyLevelValidationParameterManagerImpl{
		StateFetcher:     s,
		PolicyTranslator: &toApplicationPolicyTranslator{},
	}
	eval := statebased.NewV20Evaluator(vpmgr, pe, cor, s)
	sbv := statebased.NewKeyLevelValidator(eval, vpmgr)

	return &Validator{
		capabilities:        c,
		stateFetcher:        s,
		deserializer:        d,
		policyEvaluator:     pe,
		stateBasedValidator: sbv,
	}
}

// Validator implements the default transaction validation policy,
// which is to check the correctness of the read-write set and the endorsement
// signatures against an endorsement policy that is supplied as argument to
// every invoke
type Validator struct {
	deserializer        vi.IdentityDeserializer
	capabilities        vc.Capabilities
	stateFetcher        vs.StateFetcher
	policyEvaluator     vp.PolicyEvaluator
	stateBasedValidator StateBasedValidator
}

type validationArtifacts struct {
	rwset        []byte
	prp          []byte
	endorsements []*peer.Endorsement
	chdr         *common.ChannelHeader
	env          *common.Envelope
	payl         *common.Payload
	cap          *peer.ChaincodeActionPayload
}

func (vscc *Validator) extractValidationArtifacts(
	block *common.Block,
	txPosition int,
	actionPosition int,
) (*validationArtifacts, error) {
	// get the envelope...
	env, err := protoutil.GetEnvelopeFromBlock(block.Data.Data[txPosition])
	if err != nil {
		logger.Errorf("VSCC error: GetEnvelope failed, err %s", err)
		return nil, err
	}

	// ...and the payload...
	payl, err := protoutil.UnmarshalPayload(env.Payload)
	if err != nil {
		logger.Errorf("VSCC error: GetPayload failed, err %s", err)
		return nil, err
	}

	chdr, err := protoutil.UnmarshalChannelHeader(payl.Header.ChannelHeader)
	if err != nil {
		return nil, err
	}

	// validate the payload type
	if common.HeaderType(chdr.Type) != common.HeaderType_ENDORSER_TRANSACTION {
		logger.Errorf("Only Endorser Transactions are supported, provided type %d", chdr.Type)
		err = fmt.Errorf("Only Endorser Transactions are supported, provided type %d", chdr.Type)
		return nil, err
	}

	// ...and the transaction...
	tx, err := protoutil.UnmarshalTransaction(payl.Data)
	if err != nil {
		logger.Errorf("VSCC error: GetTransaction failed, err %s", err)
		return nil, err
	}

	cap, err := protoutil.UnmarshalChaincodeActionPayload(tx.Actions[actionPosition].Payload)
	if err != nil {
		logger.Errorf("VSCC error: GetChaincodeActionPayload failed, err %s", err)
		return nil, err
	}

	pRespPayload, err := protoutil.UnmarshalProposalResponsePayload(cap.Action.ProposalResponsePayload)
	if err != nil {
		err = fmt.Errorf("GetProposalResponsePayload error %s", err)
		return nil, err
	}
	if pRespPayload.Extension == nil {
		err = fmt.Errorf("nil pRespPayload.Extension")
		return nil, err
	}
	respPayload, err := protoutil.UnmarshalChaincodeAction(pRespPayload.Extension)
	if err != nil {
		err = fmt.Errorf("GetChaincodeAction error %s", err)
		return nil, err
	}

	return &validationArtifacts{
		rwset:        respPayload.Results,
		prp:          cap.Action.ProposalResponsePayload,
		endorsements: cap.Action.Endorsements,
		chdr:         chdr,
		env:          env,
		payl:         payl,
		cap:          cap,
	}, nil
}

// Validate validates the given envelope corresponding to a transaction with an endorsement
// policy as given in its serialized form.
// Note that in the case of dependencies in a block, such as tx_n modifying the endorsement policy
// for key a and tx_n+1 modifying the value of key a, Validate(tx_n+1) will block until Validate(tx_n)
// has been resolved. If working with a limited number of goroutines for parallel validation, ensure
// that they are allocated to transactions in ascending order.
func (vscc *Validator) Validate(
	block *common.Block,
	namespace string,
	txPosition int,
	actionPosition int,
	policyBytes []byte,
) commonerrors.TxValidationError {
	vscc.stateBasedValidator.PreValidate(uint64(txPosition), block)

	va, err := vscc.extractValidationArtifacts(block, txPosition, actionPosition)
	if err != nil {
		vscc.stateBasedValidator.PostValidate(namespace, block.Header.Number, uint64(txPosition), err)
		return policyErr(err)
	}
	
	//
	//Here our logic
	//

	//Here we use GetMSPs to get number of orgs in channel	
	n := 5
	
	//We can get this number form transaction (how many certficates in transaction)
	k := 3
	
	
	//This map create serial number for every MSPid for HashToEndorsers logic
	var m map[string]int
	m = make(map[string]int)
	m["Org1MSP"] = 1
	m["Org2MSP"] = 2
	m["Org3MSP"] = 3
	m["Org4MSP"] = 4
	m["Org5MSP"] = 5
	
	
	//Here we get MSPids from transaction assuming that k = 3
	endorsers := make([]int, k)
	endorsers[0] = m[string(va.endorsements[0].GetEndorser())]
	endorsers[1] = m[string(va.endorsements[1].GetEndorser())]
	endorsers[2] = m[string(va.endorsements[2].GetEndorser())]
	sort.Ints(endorsers)

	h := block.Header.GetDataHash()
	var h1 *[32]byte
	h1 = byte32(h)
	propEndorsers := make([]int, k)
	
	//here we make array of MSPids number which have to sign this transaction according to random generation
	propEndorsers = HashToEndorsers(*h1, n, k)
	sort.Ints(propEndorsers)
	
	
	//Here we compare array of proposal MSPids and MSPids we get from transaction to make sure that
	//endorsment of this transaction matches the random generation based on hash of any block among
	//last t blocks.
	//In this example, we are doing two iterations of checking the endorsement for randomness.
	//Below there is an example of logic for depth t where you need to learn how to get hashes of blocks of depth more than two
	if EqualVectors(propEndorsers, endorsers, k) != true {
	
		h = block.Header.GetPreviousHash()
		
		h1 = byte32(h)
		
		propEndorsers = HashToEndorsers(*h1, n, k)
		sort.Ints(propEndorsers)
		
		if EqualVectors(propEndorsers, endorsers, k) != true {
		
			fmt.Errorf("Endorsement policy of this transaction does not generated randomly!!!!")
			return nil
		
		}
		
	}
	
	fmt.Printf("Endorsement policy of this transaction matches random selection!!!!")
	
	//
	///////
	//

	txverr := vscc.stateBasedValidator.Validate(
		namespace,
		block.Header.Number,
		uint64(txPosition),
		va.rwset,
		va.prp,
		policyBytes,
		va.endorsements,
	)
	if txverr != nil {
		logger.Errorf("VSCC error: stateBasedValidator.Validate failed, err %s", txverr)
		vscc.stateBasedValidator.PostValidate(namespace, block.Header.Number, uint64(txPosition), txverr)
		return txverr
	}

	vscc.stateBasedValidator.PostValidate(namespace, block.Header.Number, uint64(txPosition), nil)
	return nil
}

func policyErr(err error) *commonerrors.VSCCEndorsementPolicyError {
	return &commonerrors.VSCCEndorsementPolicyError{
		Err: err,
	}
}

//This function accepts a hash, the total number of organizations and the number of organizations required for the endorsement.
//As a result, we get a set of non-repeating organizations for endorsement.
func HashToEndorsers(BlockHash [32]byte, n int, k int) []int {
	
	//n - number of orgs
	//k - number of orgs needed for endorsment

	var m map[uint8]bool
	m = make(map[uint8]bool)
	var buf [32]uint8
	endorsers := make([]int, k)
	var h [32]byte
	h = BlockHash

	count := 0
	i := 0
	
	for count < k {
		
		i = 0
		for i <= 31 {
			if	 count == k {
				break
			}
			buf[i] = uint8(int(h[i]) % n)
			if m[buf[i]] == false {
				endorsers[count] = int(buf[i])
				count = count + 1
			}
			i = i + 1
		}
		h = sha256.Sum256(h[:])
	}
	return endorsers
}

/*



//This is the logic that we mentioned above for checking a set of endorsers for randomness
//when it is possible to descend blocks to a depth of t
func CheckRandomEndorsers(endorsers []uint8, t int, n int, k int, block *common.Block) (bool, error) {

	//n - number of orgs
	//k - number of orgs needed for endorsment
	//t - number of blocks we have to check for randomness in hash
	
	//we have to get hash of last blocks
	//here we just genarate random hash
	//h := sha256.Sum256([]byte("Not Random text")
	
	h := block.Header.GetDataHash()
	var h1 *[32]byte
	h1 = byte32(h)
	buf := make([]uint8, k)
	i := 0 //counter from 0 to t
	for i <= t {
		buf = HashToEndorsers(*h1, n, k)
		if EqualVectors(buf, endorsers, k) == true {
			return true, nil
		}
		i = i + 1
		//here we have to go deep into next block
		//h = sha256.Sum256(h)
		h = block.Header.GetPreviousHash()
		h1 = byte32(h)
	}
	return false, nil
} */

func EqualVectors(v1 []int, v2 []int, k int) bool {
	i := 0
	for i < k {
		if v1[i] != v2[i] {
			return false
		}
		i = i + 1
	}
	return true
}

func byte32(s []byte) (a *[32]byte) {
    if len(a) <= len(s) {
        a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
    }
    return a
}
