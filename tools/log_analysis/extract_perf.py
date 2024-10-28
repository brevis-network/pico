'''
Read a log file and extract the performance data into a csv file
'''

def extract_to_csv(in_path, out_path):
    perf_data = PerformanceData()

    perf_lines = perf_data.read_raw_data(in_path)

    for line in perf_lines:
        perf_data.push_data(line)

    perf_data.save_to_csv(out_path)


# a class containing 4 domains: machine, step, chip and time
# This data structure will be saved as a csv file for later use
class PerformanceData:
    def __init__(self):
        self.machine = ""
        self.chunk = ""
        self.phase = ""
        self.step = ""
        self.chip = ""
        self.time = ""
        self.perf = ""

        self.machine_list = []
        self.chunk_list = []
        self.phase_list = []
        self.step_list = []
        self.chip_list = []
        self.time_list = []
        self.perf_list = []

    def read_raw_data(self, file_path):
        with open(file_path, 'r') as file:
            content = file.read()
    
        # all performance data lines contains "PERF"
        # ignore the preprocessed lines
        perf_lines = [line.split()[-1] for line in content.split('\n') if ("PERF" in line and not "preprocessed" in line)]
        print(len(perf_lines))

        return perf_lines
    
    def output_line(self, index):
        return f"{self.machine_list[index]},{self.chunk_list[index]},{self.phase_list[index]},{self.step_list[index]},{self.chip_list[index]},{self.time_list[index]},{self.perf_list[index]}"

    def push_data(self, line):
        flag_push = self.update_data(line)

        if flag_push:
            self.machine_list.append(self.machine)
            self.chunk_list.append(self.chunk)
            self.phase_list.append(self.phase)
            self.step_list.append(self.step)
            self.chip_list.append(self.chip)
            self.time_list.append(self.time)
            self.perf_list.append(self.perf)

    def update_data(self, line):
        entries = line.split('-')[1:]
        print(entries)

        if entries[0].startswith("machine"):
            self.machine = entries[0].split('=')[1]
            self.chunk = ""
            self.phase = ""
            self.step = ""
            self.chip = ""
            self.time = ""
            self.perf = ""
            return False

        if entries[0].startswith("phase"):
            self.chunk = ""
            self.phase = entries[0].split('=')[1]
            self.step = ""
            self.chip = ""
            self.time = ""
            self.perf = ""
            return False

        assert entries[0].startswith("step") 

        self.step = entries[0].split('=')[1]
        if self.step in ["verify", "prove", "setup_keys"]:
            self.chunk = ""
            self.phase = ""
            self.chip = ""
            self.time = ""
            self.perf = entries[1].split('=')[1]
        elif self.step == "proof_size":
            self.chunk = ""
            self.phase = ""
            self.chip = ""
            self.time = ""
            self.perf = entries[1]

        else:
            assert entries[1].startswith("chunk")
            self.chunk = entries[1].split('=')[1]

            if entries[2].startswith("chip"):
                self.chip = entries[2].split('=')[1]
                assert entries[3].startswith("cpu_time")
                self.time = "cpu_time"
                self.perf = entries[3].split('=')[1]
            else:
                assert entries[2].startswith("user_time")
                self.chip = ""
                self.time = "user_time"
                self.perf = entries[2].split('=')[1]

        return True

    # save all lists to a csv file
    def save_to_csv(self, file_path):
        with open(file_path, 'w') as file:
            file.write("machine,chunk,phase,step,chip,time,perf\n")
            for i in range(len(self.machine_list)):
                file.write(self.output_line(i) + '\n')


if __name__ == "__main__":
    prefix = 'sp1_2_large'

    in_path = f'logs/test_{prefix}.log'
    out_path = f'logs/perf_{prefix}.csv'

    extract_to_csv(in_path, out_path)
