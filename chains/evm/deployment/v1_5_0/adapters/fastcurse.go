package adapters

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	fcutil "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/rmn"
	rmnsequences "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/rmn_contract"
	api "github.com/smartcontractkit/chainlink-ccip/deployment/fastcurse"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"
)

type CurseAdapter struct {
	caches fcutil.CurseAdapterCaches
}

func NewCurseAdapter() *CurseAdapter {
	return &CurseAdapter{caches: fcutil.NewCurseAdapterCaches()}
}

func (ca *CurseAdapter) Initialize(e cldf.Environment, selector uint64) error {
	if err := ca.caches.EnsureRouter(e, selector); err != nil {
		return err
	}
	if _, ok := ca.caches.RMN(selector); ok {
		return nil
	}
	rmnAddr, err := fcutil.RMNAddressOnChain(
		e,
		selector,
		datastore.ContractType(ops.ContractType),
		semver.MustParse("1.5.0"),
	)
	if err != nil {
		return err
	}
	ca.caches.SetRMN(selector, rmnAddr)
	return nil
}

func (ca *CurseAdapter) IsSubjectCursedOnChain(e cldf.Environment, selector uint64, subject api.Subject) (bool, error) {
	rmnAddr, ok := ca.caches.RMN(selector)
	if !ok {
		return false, fmt.Errorf("no RMN address cached for chain %d", selector)
	}
	chain, err := fcutil.EVMChain(e, selector)
	if err != nil {
		return false, err
	}
	rmnC, err := rmn_contract.NewRMNContract(rmnAddr, chain.Client)
	if err != nil {
		return false, fmt.Errorf("failed to instantiate RMN contract at %s on chain %d: %w", rmnAddr, chain.Selector, err)
	}
	curseProgress, err := rmnC.GetCurseProgress(&bind.CallOpts{Context: e.GetContext()}, subject)
	if err != nil {
		return false, fmt.Errorf("failed to get curse progress for subject %x on chain %d: %w", subject, chain.Selector, err)
	}
	return curseProgress.Cursed, nil
}

func (ca *CurseAdapter) IsChainConnectedToTargetChain(e cldf.Environment, selector uint64, targetSel uint64) (bool, error) {
	routerAddr, ok := ca.caches.Router(selector)
	if !ok {
		return false, fmt.Errorf("no router address cached for chain %d", selector)
	}
	return fcutil.IsChainConnectedToTargetChain(e, routerAddr, selector, targetSel)
}

func (ca *CurseAdapter) IsCurseEnabledForChain(e cldf.Environment, selector uint64) (bool, error) {
	if _, ok := ca.caches.RMN(selector); !ok {
		return false, fmt.Errorf("no RMN address cached for chain %d", selector)
	}
	return true, nil
}

func (ca *CurseAdapter) SubjectToSelector(subject api.Subject) (uint64, error) {
	return api.GenericSubjectToSelector(subject)
}

func (ca *CurseAdapter) SelectorToSubject(selector uint64) api.Subject {
	return api.GenericSelectorToSubject(selector)
}

func (ca *CurseAdapter) Curse() *cldf_ops.Sequence[api.CurseInput, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return cldf_ops.NewSequence(
		"curse_rmn",
		semver.MustParse("1.0.0"),
		"Cursing subjects with RMN",
		func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, in api.CurseInput) (output sequences.OnChainOutput, err error) {
			chain, ok := chains.EVMChains()[in.ChainSelector]
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("chain with selector %d not found in environment", in.ChainSelector)
			}
			rmnAddr, ok := ca.caches.RMN(chain.Selector)
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("no RMN address cached for chain %d", chain.Selector)
			}
			cfgDetailsOp, err := cldf_ops.ExecuteOperation(b, ops.GetConfigDetails, chain, contract.FunctionInput[any]{
				Address:       rmnAddr,
				ChainSelector: chain.Selector,
			})
			if err != nil {
				return sequences.OnChainOutput{}, fmt.Errorf("failed to get config details for RMN at %s on chain %d: %w", rmnAddr, chain.Selector, err)
			}
			curseID, err := generateCurseID(cfgDetailsOp.Output.Version, in.Subjects)
			if err != nil {
				return sequences.OnChainOutput{}, fmt.Errorf("failed to generate curse ID for RMN at %s on chain %d: %w", rmnAddr, chain.Selector, err)
			}
			seqOutput, err := cldf_ops.ExecuteSequence(b, rmnsequences.SeqCurse, chain, rmnsequences.SeqCurseInput{
				CurseInput: in,
				Addr:       rmnAddr,
				CurseID:    curseID,
			})
			if err != nil {
				return sequences.OnChainOutput{}, fmt.Errorf("failed to curse subjects on chain %d: %w", chain.Selector, err)
			}
			output.BatchOps = append(output.BatchOps, seqOutput.Output.BatchOps...)
			return output, nil
		})
}

func (ca *CurseAdapter) Uncurse() *cldf_ops.Sequence[api.CurseInput, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return cldf_ops.NewSequence(
		"uncurse_rmn",
		semver.MustParse("1.0.0"),
		"Uncursing subjects with RMN",
		func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, in api.CurseInput) (output sequences.OnChainOutput, err error) {
			chain, ok := chains.EVMChains()[in.ChainSelector]
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("chain with selector %d not found in environment", in.ChainSelector)
			}
			rmnAddr, ok := ca.caches.RMN(chain.Selector)
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("no RMN address cached for chain %d", chain.Selector)
			}
			requests := make([]rmn_contract.RMNOwnerUnvoteToCurseRequest, 0)
			for _, subject := range in.Subjects {
				curseProgressRep, err := cldf_ops.ExecuteOperation(b, ops.GetCurseProgress, chain, contract.FunctionInput[api.Subject]{
					Address:       rmnAddr,
					ChainSelector: chain.Selector,
					Args:          subject,
				})
				if err != nil {
					return sequences.OnChainOutput{}, fmt.Errorf("failed to get curse progress for subject %x on chain %d: %w", subject, chain.Selector, err)
				}
				for i, cp := range curseProgressRep.Output.CurseVoteAddrs {
					requests = append(requests, rmn_contract.RMNOwnerUnvoteToCurseRequest{
						CurseVoteAddr: cp,
						Unit: rmn_contract.RMNUnvoteToCurseRequest{
							Subject:    subject,
							CursesHash: curseProgressRep.Output.CursesHashes[i],
						},
					})
				}
			}
			seqOutput, err := cldf_ops.ExecuteSequence(b, rmnsequences.SeqUncurse, chain, rmnsequences.SeqUncurseInput{
				Addr:     rmnAddr,
				Requests: requests,
			})
			if err != nil {
				return sequences.OnChainOutput{}, fmt.Errorf("failed to curse subjects on chain %d: %w", chain.Selector, err)
			}
			output.BatchOps = append(output.BatchOps, seqOutput.Output.BatchOps...)
			return output, nil
		})
}

func (ca *CurseAdapter) ListConnectedChains(e cldf.Environment, selector uint64) ([]uint64, error) {
	routerAddr, ok := ca.caches.Router(selector)
	if !ok {
		return nil, fmt.Errorf("no router address cached for chain %d", selector)
	}
	return fcutil.ListConnectedChains(e, routerAddr, selector)
}

func (ca *CurseAdapter) DeriveCurseAdapterVersion(e cldf.Environment, selector uint64) (*semver.Version, error) {
	return fcutil.ActiveRMNVersion(e, selector)
}

func generateCurseID(cfgVersion uint32, subjects [][16]byte) ([16]byte, error) {
	var out [16]byte

	h := sha256.New()

	err := binary.Write(h, binary.BigEndian, cfgVersion)
	if err != nil {
		return [16]byte{}, err
	}

	for _, s := range subjects {
		h.Write(s[:])
	}

	sum := h.Sum(nil)
	copy(out[:], sum[:16])
	binary.BigEndian.PutUint32(out[0:4], cfgVersion)

	return out, nil
}
