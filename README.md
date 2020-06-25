# <h1 align="center"> RenVM MPC </h1>

<p align="center">RenVM's Secure Multi-Party Computation Protocol</p>

![Build](https://github.com/renproject/mpc/workflows/test/badge.svg)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

--------------------------------------------------------------------------------

This is an implementation of a threshold ECDSA scheme, that is for use in RenVM. For a network of `n` parties, this scheme is robustly secure against `t` malicious adversaries, such that `n >= 3t + 1`. During both ECDSA key generation and signing, up to `t` parties can go offline at the beginning, middle, or end of a round, and the protocols will complete successfully without the need to go back repeat from a prior round.

## Overview
**MPC Primitives** are the building blocks for threshold ECDSA, namely [BRNG](brng/), [RNG](rng/) and [RKPG](rkpg/), are implemented in their own packages. We make use of Pedersen's [Commitment Scheme](https://link.springer.com/chapter/10.1007/3-540-46766-1_9) to augment Shamir's [Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) to a Verifiable Secret Sharing Scheme, which is implemented as a separate package.

#### Finite State Machine
MPC primitives are implemented as [finite-state machines](https://en.wikipedia.org/wiki/Finite-state_machine). A general state transitional behaviour is described below.

A `Primitive` in some `State` receives messages of the form `Transition*` with one or more message arguments. On receiving such a message, the `Primitive` must:
* Preliminary checks
    * Ensure that it is in an appropriate state to process the message
    * Ensure that the message arguments are valid
* Process message
    * Do the necessary computations with the message arguments
    * Do the necessary state transition
* Return an appropriate event that describes
    * If the machine has transitioned
    * How the machine has processed the message
    * Whether the message arguments were invalid

For more information regarding various primitive protocols and their state transitions, refer [RenVM MPC's Wiki](https://github.com/renproject/mpc/wiki).

#### Development Status
- [x] Open
- [ ] Biased Random Number Generation
- [ ] Unbiased Random Number Generation
- [ ] Random Zero Generation
- [ ] Random KeyPair Generation
- [ ] Multiply and Open
- [ ] Inversion
- [ ] Threshold ECDSA

## License
RenVM MPC is [GNU GPL v3](./LICENSE) licensed

--------------------------------------------------------------------------------

Built with ❤ by Ren.
