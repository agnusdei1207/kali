# SCP Command Reference

## Basic Usage

SCP (Secure Copy Protocol) allows secure file transfer between hosts.

### File Transfer Examples

**Download a file from remote server to local machine:**

```bash
scp -i test.pem ubuntu@123.123.123.123:/home/ubuntu/backups/test.dump C:/workspace/test/
```

**Connect to remote server with key:**

```bash
ssh -i workspace/private-keys/t.pem ubuntu@123.123.123.123
```

## Troubleshooting

### Host Key Verification Failed

When you see this error:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
```

**Possible causes:**

- IP has been reassigned to a different machine
- Host operating system was reinstalled
- SSH server was reinstalled/reconfigured
- You're connecting to a different machine with the same IP
- (Worst case) Man-in-the-middle attack

### Solutions

**Option 1: Remove the offending key (if you're sure it's safe):**

```bash
sed -i '54d' /c/Users/tester/.ssh/known_hosts
```

_This removes line 54 from known_hosts file where the conflicting key is stored_

**Option 2: Update the host key (safer approach):**

```bash
ssh-keygen -R 123.123.123.123
```

_This removes all keys for the host and prompts for new key verification on next connection_
