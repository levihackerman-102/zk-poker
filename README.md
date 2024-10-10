
# zk-poker: Zero-Knowledge Poker with Mental Poker Protocol

This project is an implementation of Texas Hold'em poker using cryptographic techniques, particularly focusing on zero-knowledge (ZK) proofs and the mental poker protocol. The project leverages the [geometryxyz/mental-poker](https://github.com/geometryxyz/mental-poker) library to ensure fairness and privacy in card shuffling and dealing without a trusted third party.

## Overview

Zero-knowledge poker (zk-poker) allows players to participate in a poker game while maintaining privacy for the cards, preventing anyone, including the dealer, from knowing other players' cards. This is achieved through Verifiable l-out-of-l threshold masking functions (VTMFs). Currently, this is just a PoC for how an actual game might look.

## Key Features

- **Fair Card Shuffling**: Using the mental poker protocol, cards are shuffled and dealt without revealing any information to other players.
- **Privacy Preserving**: No one knows the cards of other players, and zero-knowledge proofs ensure the integrity of the game.
- **No Trusted Dealer**: The need for a trusted third party is eliminated by using cryptographic methods to shuffle and deal cards.
  
## References

- [Mental Poker in the Age of SNARKs (Part 1)](https://geometry.xyz/notebook/mental-poker-in-the-age-of-snarks-part-1): A comprehensive introduction to how mental poker works and the role of SNARKs in modern cryptographic protocols.
- [zkPoker - Mental Poker in Rust](https://hackmd.io/@nmohnblatt/SJKJfVqzq): An excellent write-up on how mental poker protocols are implemented using zero-knowledge proofs.

## How It Works

1. **Card Dealing**: Cards are shuffled using a cryptographic random shuffle method, ensuring that no one, including the dealer, knows the card order.
2. **Game Flow**: Each player receives their private cards, and the game proceeds through the normal phases of Texas Hold'em poker (flop, turn, and river).
3. **Zero-Knowledge Proofs**: Throughout the game, players can prove compliance with the rules without revealing their hand.

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/zk-poker.git
   cd zk-poker
   ```

2. Follow the instructions in the [mental-poker](https://github.com/geometryxyz/mental-poker) repository for setup and dependencies.

3. Build and run the project:
   ```bash
   cargo build
   cargo run
   ```

## To-Do Features

1. **Per-Round Betting**: Implement betting mechanics for each round of the game (pre-flop, post-flop, turn, river) to simulate a complete poker experience.
2. **Code Modularization**: Refactor the code to make it more modular and easier to extend and maintain.
3. **Token Support for Betting**: Add the ability to use real tokens for betting, integrating a cryptocurrency payment system for in-game bets.

---
