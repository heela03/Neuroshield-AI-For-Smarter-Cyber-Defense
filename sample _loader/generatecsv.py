import pandas as pd
import random

# Columns
columns = ['src_ip','dst_ip','protocol','src_port','dst_port','packets','bytes','duration','flags','attack_type']

# Protocols and flags
protocols = ['TCP','UDP','ICMP','HTTP']
flags = ['SYN','ACK','PSH','FIN','-']

# Attack types
attack_types = [
    'Normal',
    'DDoS',
    'PortScan',
    'BruteForce',
    'SQLInjection',
    'XSS',
    'Botnet',
    'Infiltration',
    'DoS Slowloris',
    'Heartbleed'
]

def generate_rows(n, attack_type):
    rows = []
    for _ in range(n):
        src_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
        dst_ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
        protocol = random.choice(protocols)
        src_port = random.randint(1024,65535)
        dst_port = random.randint(20,8080)

        # Attack-specific patterns
        if attack_type == 'Normal':
            packets = random.randint(1,200)
            bytes_ = packets*random.randint(50,500)
        elif attack_type == 'DDoS':
            packets = random.randint(1000,5000)
            bytes_ = packets*random.randint(500,1500)
            # Multiple attackers: simulate by random src_ip
        elif attack_type == 'PortScan':
            packets = random.randint(1,20)
            bytes_ = packets*random.randint(20,100)
            dst_port = random.randint(1,1024)
        elif attack_type == 'BruteForce':
            packets = random.randint(50,200)
            bytes_ = packets*random.randint(200,500)
            dst_port = 22
        elif attack_type == 'SQLInjection':
            packets = random.randint(10,100)
            bytes_ = packets*random.randint(500,2000)
            dst_port = 3306
            protocol = 'HTTP'
        elif attack_type == 'XSS':
            packets = random.randint(5,50)
            bytes_ = packets*random.randint(500,1500)
            dst_port = 80
            protocol = 'HTTP'
        elif attack_type == 'Botnet':
            packets = random.randint(100,1000)
            bytes_ = packets*random.randint(300,1000)
        elif attack_type == 'Infiltration':
            packets = random.randint(50,300)
            bytes_ = packets*random.randint(500,2000)
        elif attack_type == 'DoS Slowloris':
            packets = random.randint(500,1500)
            bytes_ = packets*random.randint(200,600)
            protocol = 'HTTP'
            dst_port = 80
        elif attack_type == 'Heartbleed':
            packets = random.randint(10,50)
            bytes_ = packets*random.randint(1000,3000)
            dst_port = 443
            protocol = 'TCP'

        duration = round(random.uniform(1,300),2)
        flag = random.choice(flags)
        rows.append([src_ip,dst_ip,protocol,src_port,dst_port,packets,bytes_,duration,flag,attack_type])
    return rows

# Generate 9 mixed attack datasets + 1 pure Normal
mixed_dataframes = {}

# 9 attacks
for attack in attack_types[1:]:
    normal_rows = generate_rows(50,'Normal')
    attack_rows = generate_rows(50,attack)
    mixed = normal_rows + attack_rows
    random.shuffle(mixed)
    df = pd.DataFrame(mixed, columns=columns)
    mixed_dataframes[f"{attack}_mixed"] = df

# Pure Normal
pure_normal = pd.DataFrame(generate_rows(100,'Normal'), columns=columns)
mixed_dataframes["Normal_only"] = pure_normal

# Save all CSV files
for name, df in mixed_dataframes.items():
    df.to_csv(f"{name}.csv", index=False)

print("All 10 CSV files generated successfully!")
