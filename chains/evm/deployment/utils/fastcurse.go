package utils

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_evm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	evmds "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/datastore"
	routerops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	fcapi "github.com/smartcontractkit/chainlink-ccip/deployment/fastcurse"
	datastore_utils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
)

// CurseAdapterCaches holds per-chain RMN and router addresses for curse adapters.
type CurseAdapterCaches struct {
	RMNAddress    map[uint64]common.Address
	RouterAddress map[uint64]common.Address
}

func NewCurseAdapterCaches() CurseAdapterCaches {
	return CurseAdapterCaches{
		RMNAddress:    make(map[uint64]common.Address),
		RouterAddress: make(map[uint64]common.Address),
	}
}

func (c *CurseAdapterCaches) SetRMN(selector uint64, addr common.Address) {
	c.RMNAddress[selector] = addr
}

func (c *CurseAdapterCaches) RMN(selector uint64) (common.Address, bool) {
	addr, ok := c.RMNAddress[selector]
	return addr, ok
}

func (c *CurseAdapterCaches) Router(selector uint64) (common.Address, bool) {
	addr, ok := c.RouterAddress[selector]
	return addr, ok
}

func (c *CurseAdapterCaches) EnsureRouter(e cldf.Environment, selector uint64) error {
	if _, ok := c.RouterAddress[selector]; ok {
		return nil
	}
	addr, err := RouterAddressOnChain(e, selector)
	if err != nil {
		return fmt.Errorf("failed to find router address on chain %d: %w", selector, err)
	}
	c.RouterAddress[selector] = addr
	return nil
}

func RouterAddressOnChain(e cldf.Environment, selector uint64) (common.Address, error) {
	routerRef := datastore.AddressRef{
		Type:    datastore.ContractType(routerops.ContractType),
		Version: semver.MustParse("1.2.0"),
	}
	addr, err := datastore_utils.FindAndFormatRef(e.DataStore, routerRef, selector, evmds.ToEVMAddress)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to resolve router ref on chain with selector %d: %w", selector, err)
	}
	return addr, nil
}

func RMNAddressOnChain(
	e cldf.Environment,
	selector uint64,
	contractType datastore.ContractType,
	version *semver.Version,
) (common.Address, error) {
	rmnRef := datastore.AddressRef{
		Type:    contractType,
		Version: version,
	}
	addr, err := datastore_utils.FindAndFormatRef(e.DataStore, rmnRef, selector, evmds.ToEVMAddress)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to resolve RMN ref on chain with selector %d: %w", selector, err)
	}
	return addr, nil
}

func IsChainConnectedToTargetChain(
	e cldf.Environment,
	routerAddr common.Address,
	selector, targetSel uint64,
) (bool, error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return false, fmt.Errorf("no EVM chain found for selector %d", selector)
	}
	routerC, err := router.NewRouter(routerAddr, chain.Client)
	if err != nil {
		return false, fmt.Errorf("failed to instantiate router contract at %s on chain %d: %w", routerAddr, chain.Selector, err)
	}
	return routerC.IsChainSupported(&bind.CallOpts{Context: e.GetContext()}, targetSel)
}

func ListConnectedChains(e cldf.Environment, routerAddr common.Address, selector uint64) ([]uint64, error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return nil, fmt.Errorf("no EVM chain found for selector %d", selector)
	}
	routerC, err := router.NewRouter(routerAddr, chain.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate router contract at %s on chain %d: %w", routerAddr, chain.Selector, err)
	}
	offRamps, err := routerC.GetOffRamps(&bind.CallOpts{Context: e.GetContext()})
	if err != nil {
		return nil, fmt.Errorf("failed to get off ramps from router at %s on chain %d: %w", routerAddr, chain.Selector, err)
	}
	connectedChains := make([]uint64, 0)
	for _, offRamp := range offRamps {
		if offRamp.OffRamp == (common.Address{}) {
			continue
		}
		family, err := chainsel.GetSelectorFamily(offRamp.SourceChainSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to get selector family for connected chain %d: %w", offRamp.SourceChainSelector, err)
		}
		if !fcapi.GetCurseRegistry().IsFamilyRegistered(family) {
			continue
		}
		connectedChains = append(connectedChains, offRamp.SourceChainSelector)
	}
	return connectedChains, nil
}

func EVMChain(e cldf.Environment, selector uint64) (cldf_evm.Chain, error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return cldf_evm.Chain{}, fmt.Errorf("no EVM chain found for selector %d", selector)
	}
	return chain, nil
}
