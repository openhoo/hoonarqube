import torch.nn as nn


class Net(nn.Module):
    def __init__(self):
        super().__init__()
        self.layer = nn.Linear(4, 2)
