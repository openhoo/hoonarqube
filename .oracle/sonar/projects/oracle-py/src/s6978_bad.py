import torch.nn as nn


class Net(nn.Module):
    def __init__(self):
        self.layer = nn.Linear(4, 2)
