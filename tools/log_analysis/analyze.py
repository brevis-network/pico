import pandas as pd
from collections import defaultdict
import json
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
import os
from extract_perf import extract_to_csv

'''
Read the performance data from a csv file
'''

# read the csv file and create a panda dataframe
def process_performance_data(in_path):
    df = pd.read_csv(in_path)

    print(df.head())

    '''
    Performance for machines
    '''

    machine_perf = dict()
    # get the `step` column of df
    machine_list = df['machine'].tolist()
    machine_index = 1
    def get_machine_name(machine_index, machine_name):
        return str(machine_index) + '-' + machine_name
    
    machine_name_mapping = dict()

    for i in range(len(machine_list)):
        # initialize machine entry
        if machine_list[i] not in machine_name_mapping.keys():
            machine_name_mapping[machine_list[i]] = get_machine_name(machine_index, df['machine'][i])
            machine_index += 1

            machine_perf[machine_name_mapping[machine_list[i]]] = dict()
            machine_perf[machine_name_mapping[machine_list[i]]]['steps'] = defaultdict(int)
            machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_main'] = 0
            machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_main_ph1'] = 0
            machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_main_ph2'] = 0
            machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_main'] = 0
            machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_main_ph1'] = 0
            machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_main_ph2'] = 0
            
        # machine process time
        if df['step'][i] == 'setup_keys':
            machine_perf[machine_name_mapping[machine_list[i]]]['setup_keys'] = int(df['perf'][i])
        if df['step'][i] == 'prove':
            machine_perf[machine_name_mapping[machine_list[i]]]['prove'] = int(df['perf'][i])
        if df['step'][i] == 'verify':
            machine_perf[machine_name_mapping[machine_list[i]]]['verify'] = int(df['perf'][i])
        if df['step'][i] == 'proof_size':
            machine_perf[machine_name_mapping[machine_list[i]]]['proof_size'] = int(df['perf'][i])
        # detailed steps
        if df['step'][i] == 'generate_main':
            if df['time'][i] == 'user_time':
                if df['phase'][i] == 1:
                    machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_main_ph1'] += int(df['perf'][i])
                elif df['phase'][i] == 2:
                    machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_main_ph2'] += int(df['perf'][i])
                else:
                    machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_main'] += int(df['perf'][i])
        if df['step'][i] == 'commit_main':
            if df['time'][i] == 'user_time':
                if df['phase'][i] == 1: 
                    machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_main_ph1'] += int(df['perf'][i])
                elif df['phase'][i] == 2:
                    machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_main_ph2'] += int(df['perf'][i])
                else:
                    machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_main'] += int(df['perf'][i])
                
        if df['step'][i] == 'generate_permutation':
            if df['time'][i] == 'user_time':
                machine_perf[machine_name_mapping[machine_list[i]]]['steps']['generate_permutation'] += int(df['perf'][i])
        if df['step'][i] == 'commit_permutation':
            if df['time'][i] == 'user_time':
                machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_permutation'] += int(df['perf'][i])
        if df['step'][i] == 'compute_quotient_values':
            if df['time'][i] == 'user_time':
                machine_perf[machine_name_mapping[machine_list[i]]]['steps']['compute_quotient'] += int(df['perf'][i])
        if df['step'][i] == 'commit_quotient':
            if df['time'][i] == 'user_time':
                machine_perf[machine_name_mapping[machine_list[i]]]['steps']['commit_quotient'] += int(df['perf'][i])
        if df['step'][i] == 'open':
            if df['time'][i] == 'user_time':
                machine_perf[machine_name_mapping[machine_list[i]]]['steps']['open'] += int(df['perf'][i])
                
    # Print the machine_perf dictionary as JSON
    print("Performance for machines:")
    print(json.dumps(machine_perf, indent=4))


    '''
    Performance for chips
    '''

    for machine in machine_perf.keys():
        machine_perf[machine]['chips'] = dict()

    for i in range(len(machine_list)):
        if df['chip'][i] != '' and df['time'][i] == 'cpu_time':
            if df['chip'][i] not in machine_perf[machine_name_mapping[machine_list[i]]]['chips']:
                machine_perf[machine_name_mapping[machine_list[i]]]['chips'][df['chip'][i]] = defaultdict(int)
            if df['step'][i] == 'generate_main':
                if df['phase'][i] == 1:
                    machine_perf[machine_name_mapping[machine_list[i]]]['chips'][df['chip'][i]]['generate_main_ph1'] += int(df['perf'][i])
                else:
                    machine_perf[machine_name_mapping[machine_list[i]]]['chips'][df['chip'][i]]['generate_main_ph2'] += int(df['perf'][i])
            elif df['step'][i] == 'generate_permutation':
                machine_perf[machine_name_mapping[machine_list[i]]]['chips'][df['chip'][i]]['generate_permutation'] += int(df['perf'][i])
            elif df['step'][i] == 'compute_quotient_values':
                machine_perf[machine_name_mapping[machine_list[i]]]['chips'][df['chip'][i]]['compute_quotient'] += int(df['perf'][i])
            else:
                print(f"Unexpected step {df['step'][i]} for chip performance")
                raise ValueError(f"Unexpected step {df['step'][i]} for chip performance")


    # Print the machine_perf dictionary for chips as JSON
    for machine in machine_perf.keys():
        print(f"Chip performances for machine {machine}:")
        print(json.dumps(machine_perf[machine]['chips'], indent=4))

    return machine_perf


'''
Performance summary
'''
# proving time and proof size data
def plot_summary(perf_data, prefix=''):
    machines = list(perf_data.keys())
    prove_times = [perf_data[machine]['prove'] for machine in machines]
    proof_sizes = [perf_data[machine]['proof_size'] / 1000 for machine in machines]

    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))

    # Plot prove times
    bars1 = ax1.bar(machines, prove_times, width=0.4)  
    ax1.set_ylabel('Prove Time (ms)')
    ax1.set_title('Prove Time for Each Machine')
    ax1.tick_params(axis='x', rotation=45)

    # Add numbers on top of bars for prove times
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                 f'{int(height)}',
                 ha='center', va='bottom')

    # Plot proof sizes
    bars2 = ax2.bar(machines, proof_sizes, width=0.4)  
    ax2.set_ylabel('Proof Size (KB)')
    ax2.set_title('Proof Size for Each Machine')
    ax2.tick_params(axis='x', rotation=45)

    # Add numbers on top of bars for proof sizes
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                 f'{int(height)}',
                 ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig(f'{prefix}prove_summary.png')
    plt.close()


'''
Comparer performance summary
'''
# plot the summary of two cases in one plot for comparisons
def compare_summary(perf_data_0, perf_data_1, prefix_0='', prefix_1=''):
    machines = sorted(list(set(perf_data_0.keys()) | set(perf_data_1.keys())))
    
    # Calculate total prove times
    total_time_0 = sum(perf_data_0.get(machine, {}).get('prove', 0) for machine in machines)
    total_time_1 = sum(perf_data_1.get(machine, {}).get('prove', 0) for machine in machines)
    
    # For prove times, add "0-e2e" to beginning of machines list
    machines_with_total = ["0-e2e"] + machines
    prove_times_0 = [total_time_0] + [perf_data_0.get(machine, {}).get('prove', 0) for machine in machines]
    prove_times_1 = [total_time_1] + [perf_data_1.get(machine, {}).get('prove', 0) for machine in machines]
    
    # For proof sizes, use original machines list
    proof_sizes_0 = [perf_data_0.get(machine, {}).get('proof_size', 0) / 1000 for machine in machines]
    proof_sizes_1 = [perf_data_1.get(machine, {}).get('proof_size', 0) / 1000 for machine in machines]

    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))

    bar_width = 0.35
    
    # Plot prove times with total
    index_prove = np.arange(len(machines_with_total))
    bars1_0 = ax1.bar(index_prove - bar_width/2, prove_times_0, bar_width, label=prefix_0, color='darkblue')
    bars1_1 = ax1.bar(index_prove + bar_width/2, prove_times_1, bar_width, label=prefix_1, color='lightblue')
    ax1.set_ylabel('Prove Time (ms)')
    ax1.set_title('Prove Time Comparison')
    ax1.set_xticks(index_prove)
    ax1.set_xticklabels(machines_with_total, rotation=45, ha='right')
    ax1.legend()

    # Add numbers on top of bars for prove times
    for bars in [bars1_0, bars1_1]:
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                     f'{int(height)}',
                     ha='center', va='bottom', fontsize=8)

    # Plot proof sizes without total
    index_proof = np.arange(len(machines))
    bars2_0 = ax2.bar(index_proof - bar_width/2, proof_sizes_0, bar_width, label=prefix_0, color='darkgreen')
    bars2_1 = ax2.bar(index_proof + bar_width/2, proof_sizes_1, bar_width, label=prefix_1, color='lightgreen')
    ax2.set_ylabel('Proof Size (KB)')
    ax2.set_title('Proof Size Comparison')
    ax2.set_xticks(index_proof)
    ax2.set_xticklabels(machines, rotation=45, ha='right')
    ax2.legend()

    # Add numbers on top of bars for proof sizes
    for bars in [bars2_0, bars2_1]:
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                     f'{int(height)}',
                     ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig(f'{prefix_0}-{prefix_1}/compare_summary.png')
    plt.close()


'''
Step performances
'''

# Function to create a bar chart for a machine's step performances
def plot_step_performance(perf_data, prefix=''):
    machines = list(perf_data.keys())
    steps = list(perf_data[machines[0]]['steps'].keys())
    plt.figure(figsize=(12, 10))
    
    num_machines = len(machines)
    num_steps = len(steps)
    bar_height = 0.8 / num_steps
    index = np.arange(num_machines)
    
    # Define colors for each step
    step_colors = matplotlib.colormaps.get_cmap('tab20')(np.linspace(0, 1, num_steps))
    
    for i, step in enumerate(steps):
        times = [perf_data[machine]['steps'][step] for machine in machines]
        
        bars = plt.barh(index + i * bar_height, times, bar_height, 
                        color=step_colors[i], label=step)
        
        # Add numbers to the right of each bar
        for bar in bars:
            width = bar.get_width()
            plt.text(width, bar.get_y() + bar.get_height()/2.,
                     f'{int(width)}',
                     ha='left', va='center', fontsize=8)
    
    plt.ylabel('Machines')
    plt.xlabel('Time (ms)')
    plt.title('Step Performances for All Machines')
    plt.yticks(index + bar_height * (num_steps - 1) / 2, machines)
    
    plt.legend(title="Steps", loc="center left", bbox_to_anchor=(1, 0.5))

    plt.tight_layout()
    plt.savefig(f'{prefix}step_performance.png', bbox_inches='tight', dpi=400)
    plt.close()

'''
Compare step performances
'''
# Function to compare step performances of two cases
def compare_step_performance(perf_data_0, perf_data_1, prefix_0='', prefix_1=''):
    machines = list(perf_data_0.keys())
    plt.figure(figsize=(15, 10))
    
    num_machines = len(machines)
    steps = list(perf_data_0[machines[0]]['steps'].keys()) + ['prove']
    num_steps = len(steps)
    bar_height = 0.8 / (num_steps * 2)
    index = np.arange(num_machines)
    
    # Define colors for each step, including "prove"
    step_colors = matplotlib.colormaps.get_cmap('tab20')(np.linspace(0, 1, num_steps))
    
    for i, step in enumerate(steps):
        if step == 'prove':
            times_0 = [sum(perf_data_0[machine]['steps'].values()) for machine in machines]
            times_1 = [sum(perf_data_1[machine]['steps'].values()) for machine in machines]
        else:
            times_0 = [perf_data_0[machine]['steps'][step] for machine in machines]
            times_1 = [perf_data_1[machine]['steps'][step] for machine in machines]
        
        # Create darker and lighter versions of the base color
        darker_color = np.array(step_colors[i])
        darker_color[:3] *= 0.7  # Darken RGB channels
        lighter_color = np.array(step_colors[i])
        lighter_color[:3] = 1 - 0.7 * (1 - lighter_color[:3])  # Lighten RGB channels
        
        bars0 = plt.barh(index + i*2*bar_height, times_0, bar_height, 
                         color=darker_color, label=f'{step} ({prefix_0})')
        bars1 = plt.barh(index + (i*2+1)*bar_height, times_1, bar_height, 
                         color=lighter_color, label=f'{step} ({prefix_1})')
        
        # Add numbers to the right of each bar
        for bars in [bars0, bars1]:
            for bar in bars:
                width = bar.get_width()
                plt.text(width, bar.get_y() + bar.get_height()/2.,
                         f'{int(width)}',
                         ha='left', va='center', fontsize=8)
    
    plt.ylabel('Machines')
    plt.xlabel('Time (ms)')
    plt.title(f'Step Performances Comparison: {prefix_0} vs {prefix_1}')
    plt.yticks(index + bar_height * (num_steps - 0.5), machines)
    
    plt.legend(title="Steps", loc="center left", bbox_to_anchor=(1, 0.5))

    plt.tight_layout()
    plt.savefig(f'{prefix_0}-{prefix_1}/compare_step.png', bbox_inches='tight', dpi=400)
    plt.close()

'''
Chip performances
'''

# Function to create a horizontal stacked bar chart for chip performances across machines
def plot_chip_performance(perf_data, prefix=''):
    machines = list(perf_data.keys())
    chips = [sorted(list(machine['chips'].keys())) for machine in perf_data.values()]
    steps = sorted(list(perf_data[machines[0]]['chips']['Program'].keys()))

    plt.figure(figsize=(15, 10))
    
    bar_height = 0.8
    y_positions = np.arange(len(machines))
    
    # Define color map for steps
    step_colors = matplotlib.colormaps.get_cmap('tab20')(np.linspace(0, 1, 20))
    
    for i, machine in enumerate(machines):
        for j, chip in enumerate(chips[i]):
            if chip in perf_data[machine]['chips']:
                chip_data = perf_data[machine]['chips'][chip]
                total_time = sum(chip_data.values())
                
                y_pos = y_positions[i] - (j - len(chips[i])/2 + 0.5) * bar_height / len(chips[i])
                
                # Create sub-bars for each step
                step_left = 0
                for k, step in enumerate(steps):
                    if step in chip_data.keys():
                        step_time = chip_data[step]
                        plt.barh(y_pos, 
                                 step_time, height=bar_height/len(chips[i]), 
                                 left=step_left, color=step_colors[k], alpha=1, 
                                 label=step if i == 0 and j == 0 else "",
                                 edgecolor='black', linewidth=0.5)  # Add frame to each bar
                        step_left += step_time
                
                # Add text label for total time
                plt.text(total_time, y_pos, 
                         f'{int(total_time)}', va='center', ha='left', fontsize=8)
                
                # Add chip name on the y-axis
                plt.text(-0.01 * plt.xlim()[1], y_pos, chip, 
                         va='center', ha='right', fontsize=8)

    plt.xlabel('Time (ms)')
    plt.title('Chip Performances Across Machines')
    
    # Move machine names to the right side of the plot
    plt.yticks(y_positions, [])
    for i, machine in enumerate(machines):
        plt.text(plt.xlim()[1], y_positions[i], machine, 
                 va='center', ha='left', fontsize=10)
    
    # Create legend for steps only
    plt.legend(title="Steps", loc="upper left", bbox_to_anchor=(1, 1))
    
    plt.tight_layout()
    plt.savefig(f'{prefix}chip_performances.png', bbox_inches='tight', dpi=400)
    plt.close()

'''
Compare chip performances
'''
def compare_chip_performance(perf_data_0, perf_data_1, prefix_0='', prefix_1=''):
    machines = list(set(perf_data_0.keys()) | set(perf_data_1.keys()))
    chips = {machine: list(set(perf_data_0.get(machine, {}).get('chips', {}).keys()) | 
                           set(perf_data_1.get(machine, {}).get('chips', {}).keys()))
             for machine in machines}
    steps = list(set(step for perf in [perf_data_0, perf_data_1] 
                     for machine in perf.values() 
                     for chip in machine['chips'].values() 
                     for step in chip.keys()))

    # Create a subplot for each machine
    n_machines = len(machines)
    fig, axs = plt.subplots(n_machines, 1, figsize=(22, 10*n_machines))
    if n_machines == 1:
        axs = [axs]

    # Use a single color map for all subplots
    step_colors = matplotlib.colormaps.get_cmap('tab10')(np.linspace(0, 1, len(steps)))

    for machine_idx, (machine, ax) in enumerate(zip(machines, axs)):
        machine_chips = chips[machine]
        bar_height = 0.3
        bar_gap = 0.05
        chip_gap = 0.4
        
        # Calculate y positions for this machine's subplot
        y_positions = []
        current_y = 0
        
        for j, chip in enumerate(machine_chips):
            y_pos_base = current_y
            y_positions.append(y_pos_base)
            
            for case, (perf_data, prefix, offset) in enumerate([
                (perf_data_0, prefix_0, 0),
                (perf_data_1, prefix_1, bar_height + bar_gap)
            ]):
                if machine in perf_data and chip in perf_data[machine]['chips']:
                    chip_data = perf_data[machine]['chips'][chip]
                    total_time = sum(chip_data.values())
                    
                    y_pos = y_pos_base + offset
                    
                    step_left = 0
                    for k, step in enumerate(steps):
                        if step in chip_data:
                            step_time = chip_data[step]
                            color = step_colors[k]
                            if case == 1:
                                # Make the color lighter for the second case
                                color = np.array(color) * 0.7 + np.array([1, 1, 1, 0]) * 0.3
                            ax.barh(y_pos, step_time, 
                                   height=bar_height, 
                                   left=step_left, color=color,
                                   label=f"{prefix}-{step}" if machine_idx == 0 and j == 0 and case == 0 else "",
                                   edgecolor='black', linewidth=0.5)
                            step_left += step_time
                    
                    ax.text(total_time, y_pos, f'{int(total_time)}', 
                           va='center', ha='left', fontsize=8)
            
            # Add chip name in the middle of the two bars
            ax.text(-0.01 * ax.get_xlim()[1], y_pos_base + bar_height + bar_gap/2, 
                    chip, va='center', ha='right', fontsize=8)
            
            current_y += 2 * bar_height + bar_gap + chip_gap

        ax.set_xlabel('Time (ms)')
        ax.set_title(f'Chip Performances on {machine}: {prefix_0} vs {prefix_1}')
        
        # Set y-axis limits for consistent spacing
        ax.set_ylim(-1, current_y)
        
        # Remove y-axis ticks
        ax.set_yticks([])

    # Create a custom legend
    legend_elements = []
    for i, step in enumerate(steps):
        legend_elements.append(plt.Rectangle((0,0),1,1, facecolor=step_colors[i], edgecolor='black', label=f"{prefix_0}-{step}"))
        lighter_color = np.array(step_colors[i]) * 0.7 + np.array([1, 1, 1, 0]) * 0.3
        legend_elements.append(plt.Rectangle((0,0),1,1, facecolor=lighter_color, edgecolor='black', label=f"{prefix_1}-{step}"))
    
    # Add legend to the figure
    fig.legend(handles=legend_elements, title="Steps and Cases", 
              loc="center right", bbox_to_anchor=(0.98, 0.5))
    
    plt.tight_layout()
    plt.savefig(f'{prefix_0}-{prefix_1}/compare_chip.png', bbox_inches='tight', dpi=400)
    plt.close()

# main function
if __name__ == "__main__":
    '''
    extract performance data from log file
    '''
    prefix_0 = 'sp1_2_large'
    prefix_1 = 'sp1_3_large'

    for prefix in [prefix_0, prefix_1]:
        in_path = f'logs/test_{prefix}.log'
        out_path = f'logs/perf_{prefix}.csv'

        extract_to_csv(in_path, out_path)

    '''
    plot each of the two cases
    '''
    machine_perf = list()

    for prefix in [prefix_0, prefix_1]:
        # input path
        in_path = f'logs/perf_{prefix}.csv'

        # process performance data
        machine_perf.append(process_performance_data(in_path))
        # make directory if not exists
        os.makedirs(prefix, exist_ok=True)
        # plot summary
        plot_summary(machine_perf[-1], f'{prefix}/')
        # plot step performance
        plot_step_performance(machine_perf[-1], f'{prefix}/')
        # plot chip performance
        plot_chip_performance(machine_perf[-1], f'{prefix}/')

    '''
    compare the two cases
    '''
    os.makedirs(f'{prefix_0}-{prefix_1}', exist_ok=True)
    compare_summary(machine_perf[0], machine_perf[1], prefix_0, prefix_1)
    compare_step_performance(machine_perf[0], machine_perf[1], prefix_0, prefix_1)
    compare_chip_performance(machine_perf[0], machine_perf[1], prefix_0, prefix_1)
