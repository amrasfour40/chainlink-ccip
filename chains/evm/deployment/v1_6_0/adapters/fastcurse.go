package adapters

import (
	"fmt"
	"slices"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	fcutil "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils"
	ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	rmnsequences "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"
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
		semver.MustParse("1.6.0"),
	)
	if err != nil {
		return fmt.Errorf("failed to find RMN address on chain %d: %w", selector, err)
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
	rmnC, err := rmn_remote.NewRMNRemote(rmnAddr, chain.Client)
	if err != nil {
		return false, fmt.Errorf("failed to instantiate RMNRemote contract at %s on chain %d: %w", rmnAddr, chain.Selector, err)
	}
	cursedSubjects, err := rmnC.GetCursedSubjects(&bind.CallOpts{Context: e.GetContext()})
	if err != nil {
		return false, fmt.Errorf("failed to get cursed subjects on chain %d: %w", chain.Selector, err)
	}
	return slices.Contains(cursedSubjects, subject), nil
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
		return false, fmt.Errorf("no RMNRemote address cached for chain %d", selector)
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
		"curse_rmn_remote",
		semver.MustParse("1.0.0"),
		"Cursing subjects with RMNRemote",
		func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, in api.CurseInput) (output sequences.OnChainOutput, err error) {
			chain, ok := chains.EVMChains()[in.ChainSelector]
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("chain with selector %d not found in environment", in.ChainSelector)
			}
			rmnAddr, ok := ca.caches.RMN(chain.Selector)
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("no RMN address cached for chain %d", chain.Selector)
			}
			seqOutput, err := cldf_ops.ExecuteSequence(b, rmnsequences.SeqCurse, chain, rmnsequences.SeqCurseInput{
				CurseInput: in,
				Addr:       rmnAddr,
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
		"uncurse_rmn_remote",
		semver.MustParse("1.0.0"),
		"Uncursing subjects with RMNRemote",
		func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, in api.CurseInput) (output sequences.OnChainOutput, err error) {
			chain, ok := chains.EVMChains()[in.ChainSelector]
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("chain with selector %d not found in environment", in.ChainSelector)
			}
			rmnAddr, ok := ca.caches.RMN(chain.Selector)
			if !ok {
				return sequences.OnChainOutput{}, fmt.Errorf("no RMN address cached for chain %d", chain.Selector)
			}
			seqOutput, err := cldf_ops.ExecuteSequence(b, rmnsequences.SeqUncurse, chain, rmnsequences.SeqCurseInput{
				CurseInput: in,
				Addr:       rmnAddr,
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
