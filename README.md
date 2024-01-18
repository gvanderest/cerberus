# Cerberus MMO Server

NOTE: This is an experimental work in progress and should not be trusted or relied upon.  It may never be completed or even progress to a truly usable state.

This is a learning and experimentation project to create the servers for running MMO game servers in Rust.  This project will rely on information from packet analysis between the Ragnarok Online game client and its real servers, as well as research in the HerculesWS and eAthena codebases.

This is the first time I have attempted an undertaking of this kind (in general or with Rust), so the code may remain unclean for a long period of time.

## Additional Links

- [Packet Reference](https://hackmd.io/@gvanderest/cerberus) to follow research into packet structures and notes on the commands/interactions between client and servers

## Goals and Functionality

Currently have the following goals, which will be extended in the future if they're hit

- [x] Connect to login server
- [ ] Create account with "username_M" format seen on some servers
- [ ] Delete account
- [x] Select which character server to connect to
- [ ] Connect to character server
- [ ] Create character
- [ ] Delete character
- [ ] Login to game with character
- [ ] Connect to map server with a character
- [ ] Walk around
- [ ] Have monsters respawn
- [ ] Kill monsters with melee
- [ ] Have monsters walk around
- [ ] Loot items
- [ ] Drop and pick up items
- [ ] Log out
- [ ] Return to character selection
- [ ] Portals between maps and switching map servers


## Larger Goals
If/when the above list is completed, these are some that come to mind that would make sense to expand into.  Data for powering a lot of this functionality will likely be scraped from the HerculesWS and similar projects for their data configuration files.

- [ ] Use of skills/spells on monsters
- [ ] Use of skills/spells on self or other players
- [ ] Create, join, leave parties and change XP share settings
- [ ] Chatrooms
- [ ] Parser for HerculesWS or other configuration files
- [ ] Parser for GRF files to create data that represents maps
- [ ] Monster aggro and scripts, abilities
- [ ] Buffs/effects and calculations
- [ ] NPC interaction scripts/quests.. HerculesWS/other script langs and LUA
- [ ] Kafra storage
- [ ] Kafra teleport
- [ ] Warp portals
- [ ] Guilds and all the fun that comes with them
- [ ] War of Emperium or Battlegrounds and PVP in general
