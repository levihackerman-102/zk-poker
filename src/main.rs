extern crate barnett_smart_card_protocol;

use barnett_smart_card_protocol::discrete_log_cards;
use barnett_smart_card_protocol::BarnettSmartProtocol;

use anyhow;
use ark_ff::{to_bytes, UniformRand};
use ark_std::{rand::Rng, One};
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use rand::thread_rng;
use std::collections::HashMap;
use std::iter::Iterator;
use thiserror::Error;
use itertools::Itertools;

// Choose elliptic curve setting
type Curve = starknet_curve::Projective;
type Scalar = starknet_curve::Fr;

// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
type CardParameters = discrete_log_cards::Parameters<Curve>;
type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

#[derive(Error, Debug, PartialEq)]
pub enum GameErrors {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("Invalid card")]
    InvalidCard,
}

#[derive(PartialEq, Clone, Copy, Eq)]
pub enum Suite {
    Club,
    Diamond,
    Heart,
    Spade,
}

impl Suite {
    const VALUES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];
}

#[derive(PartialEq, PartialOrd, Clone, Copy, Eq, Debug, Ord, Hash)]
pub enum Value {
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Ten,
    Jack,
    Queen,
    King,
    Ace,
}

impl Value {
    const VALUES: [Self; 13] = [
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Ten,
        Self::Jack,
        Self::Queen,
        Self::King,
        Self::Ace,
    ];
}

#[derive(PartialEq, Clone, Eq, Copy)]
pub struct ClassicPlayingCard {
    value: Value,
    suite: Suite,
}

impl ClassicPlayingCard {
    pub fn new(value: Value, suite: Suite) -> Self {
        Self { value, suite }
    }
}

impl std::fmt::Debug for ClassicPlayingCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Club => "♣",
            Suite::Diamond => "♦",
            Suite::Heart => "♥",
            Suite::Spade => "♠",
        };

        let val = match self.value {
            Value::Two => "2",
            Value::Three => "3",
            Value::Four => "4",
            Value::Five => "5",
            Value::Six => "6",
            Value::Seven => "7",
            Value::Eight => "8",
            Value::Nine => "9",
            Value::Ten => "10",
            Value::Jack => "J",
            Value::Queen => "Q",
            Value::King => "K",
            Value::Ace => "A",
        };

        write!(f, "{}{}", val, suite)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum HandRank {
    HighCard(Value),
    OnePair(Value),
    TwoPair(Value, Value),
    ThreeOfAKind(Value),
    Straight(Value),
    Flush(Value),
    FullHouse(Value, Value),
    FourOfAKind(Value),
    StraightFlush(Value),
}

impl HandRank {
    fn rank(&self) -> u8 {
        match self {
            HandRank::HighCard(_) => 1,
            HandRank::OnePair(_) => 2,
            HandRank::TwoPair(_, _) => 3,
            HandRank::ThreeOfAKind(_) => 4,
            HandRank::Straight(_) => 5,
            HandRank::Flush(_) => 6,
            HandRank::FullHouse(_, _) => 7,
            HandRank::FourOfAKind(_) => 8,
            HandRank::StraightFlush(_) => 9,
        }
    }
}

impl ClassicPlayingCard {
    pub fn best_hand(cards: &[ClassicPlayingCard; 7]) -> HandRank {
        let mut best_hand = HandRank::HighCard(Value::Two); // Start with the lowest hand
        
        // Get all combinations of 5 cards from the 7 cards (2 hole cards + 5 community cards)
        let all_combinations = Self::get_combinations(cards);
        
        // Check each combination to find the highest-ranked hand
        for combination in all_combinations {
            let current_hand = Self::evaluate_hand(&combination);
            if current_hand > best_hand {
                best_hand = current_hand;
            }
        }
        
        best_hand
    }

    fn get_combinations(cards: &[ClassicPlayingCard; 7]) -> Vec<[ClassicPlayingCard; 5]> {
        let mut combinations = Vec::new();
        for combination in cards.iter().combinations(5) {
            let mut selected_cards = [cards[0]; 5];
            for (i, &card) in combination.iter().enumerate() {
                selected_cards[i] = *card;
            }
            combinations.push(selected_cards);
        }
        combinations
    }
    

    fn evaluate_hand(cards: &[ClassicPlayingCard; 5]) -> HandRank {
        // Check for hand ranks from highest to lowest
        if let Some(rank) = Self::is_straight_flush(cards) {
            return HandRank::StraightFlush(rank);
        } else if let Some(rank) = Self::is_four_of_a_kind(cards) {
            return HandRank::FourOfAKind(rank);
        } else if let Some((three, pair)) = Self::is_full_house(cards) {
            return HandRank::FullHouse(three, pair);
        } else if let Some(rank) = Self::is_flush(cards) {
            return HandRank::Flush(rank);
        } else if let Some(rank) = Self::is_straight(cards) {
            return HandRank::Straight(rank);
        } else if let Some(rank) = Self::is_three_of_a_kind(cards) {
            return HandRank::ThreeOfAKind(rank);
        } else if let Some((high_pair, low_pair)) = Self::is_two_pair(cards) {
            return HandRank::TwoPair(high_pair, low_pair);
        } else if let Some(rank) = Self::is_one_pair(cards) {
            return HandRank::OnePair(rank);
        }
        
        // If no other hand, return HighCard with the highest card value
        let highest_card = cards.iter().map(|card| card.value).max().unwrap();
        HandRank::HighCard(highest_card)
    }

    fn is_straight_flush(cards: &[ClassicPlayingCard; 5]) -> Option<Value> {
        if Self::is_flush(cards).is_some() && Self::is_straight(cards).is_some() {
            return Self::is_straight(cards);
        }
        None
    }

    fn is_four_of_a_kind(cards: &[ClassicPlayingCard; 5]) -> Option<Value> {
        let mut counts = Self::card_value_counts(cards);
        counts.retain(|&_, &mut count| count == 4);
        if let Some((&value, _)) = counts.iter().next() {
            return Some(value);
        }
        None
    }

    fn is_full_house(cards: &[ClassicPlayingCard; 5]) -> Option<(Value, Value)> {
        let mut counts = Self::card_value_counts(cards);
        counts.retain(|_, &mut count| count == 3 || count == 2);
        if counts.len() == 2 {
            let three_of_a_kind = counts.iter().find(|&(_, &count)| count == 3).unwrap().0;
            let pair = counts.iter().find(|&(_, &count)| count == 2).unwrap().0;
            return Some((*three_of_a_kind, *pair));
        }
        None
    }

    fn is_flush(cards: &[ClassicPlayingCard; 5]) -> Option<Value> {
        let first_suite = cards[0].suite;
        if cards.iter().all(|card| card.suite == first_suite) {
            let highest_card = cards.iter().map(|card| card.value).max().unwrap();
            return Some(highest_card);
        }
        None
    }

    fn is_straight(cards: &[ClassicPlayingCard; 5]) -> Option<Value> {
        let mut values: Vec<Value> = cards.iter().map(|card| card.value).collect();
        values.sort();
        if values.windows(2).all(|w| w[1] as u8 == w[0] as u8 + 1) {
            return Some(*values.last().unwrap());
        }
        None
    }

    fn is_three_of_a_kind(cards: &[ClassicPlayingCard; 5]) -> Option<Value> {
        let mut counts = Self::card_value_counts(cards);
        counts.retain(|_, &mut count| count == 3);
        if let Some((&value, _)) = counts.iter().next() {
            return Some(value);
        }
        None
    }

    fn is_two_pair(cards: &[ClassicPlayingCard; 5]) -> Option<(Value, Value)> {
        let mut counts = Self::card_value_counts(cards);
        counts.retain(|_, &mut count| count == 2);
        if counts.len() == 2 {
            let mut pairs: Vec<Value> = counts.keys().cloned().collect();
            pairs.sort();
            return Some((pairs[1], pairs[0])); // Return high pair first
        }
        None
    }

    fn is_one_pair(cards: &[ClassicPlayingCard; 5]) -> Option<Value> {
        let mut counts = Self::card_value_counts(cards);
        counts.retain(|_, &mut count| count == 2);
        if let Some((&value, _)) = counts.iter().next() {
            return Some(value);
        }
        None
    }

    fn card_value_counts(cards: &[ClassicPlayingCard; 5]) -> std::collections::HashMap<Value, usize> {
        let mut counts = std::collections::HashMap::new();
        for card in cards {
            *counts.entry(card.value).or_insert(0) += 1;
        }
        counts
    }
}

#[derive(Clone)]
struct Player {
    name: Vec<u8>,
    sk: SecretKey,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<ClassicPlayingCard>>,
    balance: u64,
}

impl Player {
    pub fn new<R: Rng>(rng: &mut R, pp: &CardParameters, name: &Vec<u8>) -> anyhow::Result<Self> {
        let (pk, sk) = CardProtocol::player_keygen(rng, pp)?;
        let proof_key = CardProtocol::prove_key_ownership(rng, pp, &pk, &sk, name)?;
        Ok(Self {
            name: name.clone(),
            sk,
            pk,
            proof_key,
            cards: vec![],
            opened_cards: vec![],
            balance: 100,
        })
    }

    pub fn receive_card(&mut self, card: MaskedCard) {
        self.cards.push(card);
        self.opened_cards.push(None);
    }

    pub fn peek_at_card(
        &mut self,
        parameters: &CardParameters,
        reveal_tokens: &mut Vec<(RevealToken, RevealProof, PublicKey)>,
        card_mappings: &HashMap<Card, ClassicPlayingCard>,
        card: &MaskedCard,
    ) -> Result<(), anyhow::Error> {
        let i = self.cards.iter().position(|&x| x == *card);

        let i = i.ok_or(GameErrors::CardNotFound)?;

        // println!("Player {} is peeking at card {}", std::str::from_utf8(&self.name).unwrap(), i);

        // TODO add function to create that without the proof
        let rng = &mut thread_rng();
        let own_reveal_token = self.compute_reveal_token(rng, parameters, card)?;
        reveal_tokens.push(own_reveal_token);

        // println!("Own reveal token added");

        let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
        // println!("Unmasked card: {:?}", unmasked_card);
        let opened_card = card_mappings.get(&unmasked_card);
        // println!("Opened card: {:?}", opened_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;

        self.opened_cards[i] = Some(*opened_card);
        Ok(())
    }

    pub fn compute_reveal_token<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
        card: &MaskedCard,
    ) -> anyhow::Result<(RevealToken, RevealProof, PublicKey)> {
        let (reveal_token, reveal_proof) =
            CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, card)?;

        Ok((reveal_token, reveal_proof, self.pk))
    }

    pub fn best_hand(&self, community_cards: &[ClassicPlayingCard]) -> HandRank {
        // Chain the player's opened cards with the community cards
        let combined_cards: Vec<&ClassicPlayingCard> = self
            .opened_cards
            .iter() // Create an iterator over the player's opened cards
            .filter_map(|card_option| card_option.as_ref()) // Filter out None and get references
            .chain(community_cards.iter()) // Chain with the community cards
            .collect(); // Collect into a Vec<&ClassicPlayingCard>

        // To calculate the best hand, we need a total of 7 cards (2 from the player and 5 from the community)
        // Since `combined_cards` now contains references, we need to convert it to a slice of 7 cards
        if combined_cards.len() != 7 {
            panic!("Incorrect number of combined cards!"); // Handle incorrect card count
        }

        // Use the best_hand function from ClassicPlayingCard to calculate the player's best hand
        let hand_rank = ClassicPlayingCard::best_hand(
            &combined_cards.iter().map(|&card| *card).collect::<Vec<_>>().try_into().unwrap()
        );

        hand_rank
    }
}

//Every player will have to calculate this function for cards that are in play
pub fn open_card(
    parameters: &CardParameters,
    reveal_tokens: &Vec<(RevealToken, RevealProof, PublicKey)>,
    card_mappings: &HashMap<Card, ClassicPlayingCard>,
    card: &MaskedCard,
) -> Result<ClassicPlayingCard, anyhow::Error> {
    let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
    let opened_card = card_mappings.get(&unmasked_card);
    let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;

    Ok(*opened_card)
}

fn encode_cards<R: Rng>(rng: &mut R, num_of_cards: usize) -> HashMap<Card, ClassicPlayingCard> {
    let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
    let plaintexts = (0..num_of_cards)
        .map(|_| Card::rand(rng))
        .collect::<Vec<_>>();

    let mut i = 0;
    for value in Value::VALUES.iter().copied() {
        for suite in Suite::VALUES.iter().copied() {
            let current_card = ClassicPlayingCard::new(value, suite);
            map.insert(plaintexts[i], current_card);
            i += 1;
        }
    }

    map
}

fn main() -> anyhow::Result<()> {
    let m = 2;
    let n = 26;
    let num_of_cards = m * n;
    let rng = &mut thread_rng();

    let parameters = CardProtocol::setup(rng, m, n)?;
    let card_mapping = encode_cards(rng, num_of_cards);

    let mut andrija = Player::new(rng, &parameters, &to_bytes![b"Andrija"].unwrap())?;
    let mut kobi = Player::new(rng, &parameters, &to_bytes![b"Kobi"].unwrap())?;
    let mut nico = Player::new(rng, &parameters, &to_bytes![b"Nico"].unwrap())?;
    let mut tom = Player::new(rng, &parameters, &to_bytes![b"Tom"].unwrap())?;

    let players = vec![andrija.clone(), kobi.clone(), nico.clone(), tom.clone()];

    let key_proof_info = players
        .iter()
        .map(|p| (p.pk, p.proof_key, p.name.clone()))
        .collect::<Vec<_>>();

    // Each player should run this computation. Alternatively, it can be ran by a smart contract
    let joint_pk = CardProtocol::compute_aggregate_key(&parameters, &key_proof_info)?;

    // Each player should run this computation and verify that all players agree on the initial deck
    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = card_mapping
        .keys()
        .map(|card| CardProtocol::mask(rng, &parameters, &joint_pk, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    // SHUFFLE TIME --------------
    // 1.a Andrija shuffles first
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (a_shuffled_deck, a_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &deck,
        &masking_factors,
        &permutation,
    )?;

    // 1.b everyone checks!
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &deck,
        &a_shuffled_deck,
        &a_shuffle_proof,
    )?;

    //2.a Kobi shuffles second
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (k_shuffled_deck, k_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &a_shuffled_deck,
        &masking_factors,
        &permutation,
    )?;

    //2.b Everyone checks
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &a_shuffled_deck,
        &k_shuffled_deck,
        &k_shuffle_proof,
    )?;

    //3.a Nico shuffles third
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (n_shuffled_deck, n_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &k_shuffled_deck,
        &masking_factors,
        &permutation,
    )?;

    //3.b Everyone checks
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &k_shuffled_deck,
        &n_shuffled_deck,
        &n_shuffle_proof,
    )?;

    //4.a Tom shuffles last
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (final_shuffled_deck, final_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &n_shuffled_deck,
        &masking_factors,
        &permutation,
    )?;

    //4.b Everyone checks before accepting last deck for game
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &n_shuffled_deck,
        &final_shuffled_deck,
        &final_shuffle_proof,
    )?;

    // CARDS ARE SHUFFLED. ROUND OF THE GAME CAN BEGIN
    let deck = final_shuffled_deck;

    let mut i = 0;

    while i < 8 {
        andrija.receive_card(deck[i]);
        kobi.receive_card(deck[i+1]);
        nico.receive_card(deck[i+2]);
        tom.receive_card(deck[i+3]);

        i += 4;
    }

    

    let andrija_rt_1 = andrija.compute_reveal_token(rng, &parameters, &deck[1])?;
    let andrija_rt_2 = andrija.compute_reveal_token(rng, &parameters, &deck[2])?;
    let andrija_rt_3 = andrija.compute_reveal_token(rng, &parameters, &deck[3])?;
    let andrija_rt_5 = andrija.compute_reveal_token(rng, &parameters, &deck[5])?;
    let andrija_rt_6 = andrija.compute_reveal_token(rng, &parameters, &deck[6])?;
    let andrija_rt_7 = andrija.compute_reveal_token(rng, &parameters, &deck[7])?;

    let kobi_rt_0 = kobi.compute_reveal_token(rng, &parameters, &deck[0])?;
    let kobi_rt_2 = kobi.compute_reveal_token(rng, &parameters, &deck[2])?;
    let kobi_rt_3 = kobi.compute_reveal_token(rng, &parameters, &deck[3])?;
    let kobi_rt_4 = kobi.compute_reveal_token(rng, &parameters, &deck[4])?;
    let kobi_rt_6 = kobi.compute_reveal_token(rng, &parameters, &deck[6])?;
    let kobi_rt_7 = kobi.compute_reveal_token(rng, &parameters, &deck[7])?;

    let nico_rt_0 = nico.compute_reveal_token(rng, &parameters, &deck[0])?;
    let nico_rt_1 = nico.compute_reveal_token(rng, &parameters, &deck[1])?;
    let nico_rt_3 = nico.compute_reveal_token(rng, &parameters, &deck[3])?;
    let nico_rt_4 = nico.compute_reveal_token(rng, &parameters, &deck[4])?;
    let nico_rt_5 = nico.compute_reveal_token(rng, &parameters, &deck[5])?;
    let nico_rt_7 = nico.compute_reveal_token(rng, &parameters, &deck[7])?;

    let tom_rt_0 = tom.compute_reveal_token(rng, &parameters, &deck[0])?;
    let tom_rt_1 = tom.compute_reveal_token(rng, &parameters, &deck[1])?;
    let tom_rt_2 = tom.compute_reveal_token(rng, &parameters, &deck[2])?;
    let tom_rt_4 = tom.compute_reveal_token(rng, &parameters, &deck[4])?;
    let tom_rt_5 = tom.compute_reveal_token(rng, &parameters, &deck[5])?;
    let tom_rt_6 = tom.compute_reveal_token(rng, &parameters, &deck[6])?;

    let mut rts_andrija_1 = vec![kobi_rt_0, nico_rt_0, tom_rt_0];
    let mut rts_andrija_2 = vec![kobi_rt_4, nico_rt_4, tom_rt_4];
    let mut rts_kobi_1 = vec![andrija_rt_1, nico_rt_1, tom_rt_1];
    let mut rts_kobi_2 = vec![andrija_rt_5, nico_rt_5, tom_rt_5];
    let mut rts_nico_1 = vec![andrija_rt_2, kobi_rt_2, tom_rt_2];
    let mut rts_nico_2 = vec![andrija_rt_6, kobi_rt_6, tom_rt_6];
    let mut rts_tom_1 = vec![andrija_rt_3, kobi_rt_3, nico_rt_3];
    let mut rts_tom_2 = vec![andrija_rt_7, kobi_rt_7, nico_rt_7];

    println!("Time to peek!");

    //At this moment players privately open their cards and only they know that values
    andrija.peek_at_card(&parameters, &mut rts_andrija_1, &card_mapping, &deck[0])?;
    kobi.peek_at_card(&parameters, &mut rts_kobi_1, &card_mapping, &deck[1])?;
    nico.peek_at_card(&parameters, &mut rts_nico_1, &card_mapping, &deck[2])?;
    tom.peek_at_card(&parameters, &mut rts_tom_1, &card_mapping, &deck[3])?;
    andrija.peek_at_card(&parameters, &mut rts_andrija_2, &card_mapping, &deck[4])?;
    kobi.peek_at_card(&parameters, &mut rts_kobi_2, &card_mapping, &deck[5])?;
    nico.peek_at_card(&parameters, &mut rts_nico_2, &card_mapping, &deck[6])?;
    tom.peek_at_card(&parameters, &mut rts_tom_2, &card_mapping, &deck[7])?;

    println!("Peeking done!");

    /* Here we can add custom logic of a game:
        1. swap card
        2. place a bet
        3. ...
    */
 
    // pre-flop round
    let ante = 10;
    let mut pot = 0;

    for mut player in players {
        player.balance -= ante;
        pot += ante;
    }

    // flop round
    let flop = vec![deck[8], deck[9], deck[10]];
    let mut flop_rts: Vec<Vec<(RevealToken, RevealProof, PublicKey)>> = vec![];
    for card in flop {
        let rt_card = vec![
            andrija.compute_reveal_token(rng, &parameters, &card)?,
            kobi.compute_reveal_token(rng, &parameters, &card)?,
            nico.compute_reveal_token(rng, &parameters, &card)?,
            tom.compute_reveal_token(rng, &parameters, &card)?,
        ];
        flop_rts.push(rt_card);
    }
    
    println!("Flop rts done!");
    
    // reveal flop
    let flop_opened: Vec<ClassicPlayingCard> = flop_rts
        .iter()
        .enumerate()
        .map(|(i, rt)| open_card(&parameters, rt, &card_mapping, &deck[i+8]).unwrap())
        .collect();
    println!("Flop opened!");
    for card in flop_opened.iter() {
        println!("Flop card: {:?}", card);
    }

    // turn round
    let turn = deck[11];
    let turn_rt: Vec<(RevealToken, RevealProof, PublicKey)> = vec![
        andrija.compute_reveal_token(rng, &parameters, &turn)?,
        kobi.compute_reveal_token(rng, &parameters, &turn)?,
        nico.compute_reveal_token(rng, &parameters, &turn)?,
        tom.compute_reveal_token(rng, &parameters, &turn)?,
    ];
    let turn_opened = open_card(&parameters, &turn_rt, &card_mapping, &turn).unwrap();
    println!("Turn opened: {:?}", turn_opened);

    // river round
    let river = deck[12];
    let river_rt: Vec<(RevealToken, RevealProof, PublicKey)> = vec![
        andrija.compute_reveal_token(rng, &parameters, &river)?,
        kobi.compute_reveal_token(rng, &parameters, &river)?,
        nico.compute_reveal_token(rng, &parameters, &river)?,
        tom.compute_reveal_token(rng, &parameters, &river)?,
    ];
    let river_opened = open_card(&parameters, &river_rt, &card_mapping, &river).unwrap();
    println!("River opened: {:?}", river_opened);

    // community cards
    let community_cards: Vec<ClassicPlayingCard> = flop_opened
    .iter()
    .chain(std::iter::once(&turn_opened))
    .chain(std::iter::once(&river_opened))
    .cloned() // Clone the references into owned ClassicPlayingCard values
    .collect();

    println!("Community cards: {:?}", community_cards);

    // calculate the winner
    let andrija_hand = andrija.best_hand(&community_cards);
    let kobi_hand = kobi.best_hand(&community_cards);
    let nico_hand = nico.best_hand(&community_cards);
    let tom_hand = tom.best_hand(&community_cards);

    println!("Andrija hand: {:?}", andrija_hand);
    println!("Kobi hand: {:?}", kobi_hand);
    println!("Nico hand: {:?}", nico_hand);
    println!("Tom hand: {:?}", tom_hand);

    // select the winner
    let mut winners = vec![];
    let mut max_rank = 0;
    for (i, hand) in [andrija_hand, kobi_hand, nico_hand, tom_hand].iter().enumerate() {
        if hand.rank() > max_rank {
            max_rank = hand.rank();
            winners = vec![i];
        } else if hand.rank() == max_rank {
            winners.push(i);
        }
    }

    // distribute the pot
    let winnings = pot / winners.len() as u64;
    for winner in winners {
        match winner {
            0 => andrija.balance += winnings,
            1 => kobi.balance += winnings,
            2 => nico.balance += winnings,
            3 => tom.balance += winnings,
            _ => unreachable!(),
        }
    }

    println!("Andrija balance: {}", andrija.balance);
    println!("Kobi balance: {}", kobi.balance);
    println!("Nico balance: {}", nico.balance);
    println!("Tom balance: {}", tom.balance);

    //1.a everyone reveals the secret for their card
    let andrija_rt_0 = andrija.compute_reveal_token(rng, &parameters, &deck[0])?;
    let kobi_rt_1 = kobi.compute_reveal_token(rng, &parameters, &deck[1])?;
    let nico_rt_2 = nico.compute_reveal_token(rng, &parameters, &deck[2])?;
    let tom_rt_3 = tom.compute_reveal_token(rng, &parameters, &deck[3])?;

    let andrija_rt_4 = andrija.compute_reveal_token(rng, &parameters, &deck[4])?;
    let kobi_rt_5 = kobi.compute_reveal_token(rng, &parameters, &deck[5])?;
    let nico_rt_6 = nico.compute_reveal_token(rng, &parameters, &deck[6])?;
    let tom_rt_7 = tom.compute_reveal_token(rng, &parameters, &deck[7])?;

    //2. tokens for all other cards are exchanged
    //TODO add struct for this so that we can just clone
    let andrija_rt_1 = andrija.compute_reveal_token(rng, &parameters, &deck[1])?;
    let andrija_rt_2 = andrija.compute_reveal_token(rng, &parameters, &deck[2])?;
    let andrija_rt_3 = andrija.compute_reveal_token(rng, &parameters, &deck[3])?;
    let andrija_rt_5 = andrija.compute_reveal_token(rng, &parameters, &deck[5])?;
    let andrija_rt_6 = andrija.compute_reveal_token(rng, &parameters, &deck[6])?;
    let andrija_rt_7 = andrija.compute_reveal_token(rng, &parameters, &deck[7])?;

    let kobi_rt_0 = kobi.compute_reveal_token(rng, &parameters, &deck[0])?;
    let kobi_rt_2 = kobi.compute_reveal_token(rng, &parameters, &deck[2])?;
    let kobi_rt_3 = kobi.compute_reveal_token(rng, &parameters, &deck[3])?;
    let kobi_rt_4 = kobi.compute_reveal_token(rng, &parameters, &deck[4])?;
    let kobi_rt_6 = kobi.compute_reveal_token(rng, &parameters, &deck[6])?;
    let kobi_rt_7 = kobi.compute_reveal_token(rng, &parameters, &deck[7])?;

    let nico_rt_0 = nico.compute_reveal_token(rng, &parameters, &deck[0])?;
    let nico_rt_1 = nico.compute_reveal_token(rng, &parameters, &deck[1])?;
    let nico_rt_3 = nico.compute_reveal_token(rng, &parameters, &deck[3])?;
    let nico_rt_4 = nico.compute_reveal_token(rng, &parameters, &deck[4])?;
    let nico_rt_5 = nico.compute_reveal_token(rng, &parameters, &deck[5])?;
    let nico_rt_7 = nico.compute_reveal_token(rng, &parameters, &deck[7])?;

    let tom_rt_0 = tom.compute_reveal_token(rng, &parameters, &deck[0])?;
    let tom_rt_1 = tom.compute_reveal_token(rng, &parameters, &deck[1])?;
    let tom_rt_2 = tom.compute_reveal_token(rng, &parameters, &deck[2])?;
    let tom_rt_4 = tom.compute_reveal_token(rng, &parameters, &deck[4])?;
    let tom_rt_5 = tom.compute_reveal_token(rng, &parameters, &deck[5])?;
    let tom_rt_6 = tom.compute_reveal_token(rng, &parameters, &deck[6])?;

    let rt_0 = vec![andrija_rt_0, kobi_rt_0, nico_rt_0, tom_rt_0];
    let rt_1 = vec![andrija_rt_1, kobi_rt_1, nico_rt_1, tom_rt_1];
    let rt_2 = vec![andrija_rt_2, kobi_rt_2, nico_rt_2, tom_rt_2];
    let rt_3 = vec![andrija_rt_3, kobi_rt_3, nico_rt_3, tom_rt_3];
    let rt_4 = vec![andrija_rt_4, kobi_rt_4, nico_rt_4, tom_rt_4];
    let rt_5 = vec![andrija_rt_5, kobi_rt_5, nico_rt_5, tom_rt_5];
    let rt_6 = vec![andrija_rt_6, kobi_rt_6, nico_rt_6, tom_rt_6];
    let rt_7 = vec![andrija_rt_7, kobi_rt_7, nico_rt_7, tom_rt_7];

    println!("Time to open!");

    //Everyone computes for each card (except for their own card):
    let andrija_card_1 = open_card(&parameters, &rt_0, &card_mapping, &deck[0])?;
    let andrija_card_2 = open_card(&parameters, &rt_4, &card_mapping, &deck[4])?;
    let kobi_card_1 = open_card(&parameters, &rt_1, &card_mapping, &deck[1])?;
    let kobi_card_2 = open_card(&parameters, &rt_5, &card_mapping, &deck[5])?;
    let nico_card_1 = open_card(&parameters, &rt_2, &card_mapping, &deck[2])?;
    let nico_card_2 = open_card(&parameters, &rt_6, &card_mapping, &deck[6])?;
    let tom_card_1 = open_card(&parameters, &rt_3, &card_mapping, &deck[3])?;
    let tom_card_2 = open_card(&parameters, &rt_7, &card_mapping, &deck[7])?;

    println!("Andrija: {:?}", andrija_card_1);
    println!("Andrija: {:?}", andrija_card_2);
    println!("Kobi: {:?}", kobi_card_1);
    println!("Kobi: {:?}", kobi_card_2);
    println!("Nico: {:?}", nico_card_1);
    println!("Nico: {:?}", nico_card_2);
    println!("Tom: {:?}", tom_card_1);
    println!("Tom: {:?}", tom_card_2);

    Ok(())
}
