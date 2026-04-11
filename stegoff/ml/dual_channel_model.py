"""
Dual-channel DistilBERT + heuristic features model.

Architecture:
    Text → DistilBERT → [CLS] embedding (768d)
    Text → Heuristic extractor → feature vector (15d)
    [768d + 15d] → Linear(783, 256) → ReLU → Dropout → Linear(256, 2)

Following DMPI-PMHFE (arxiv 2506.06384) late fusion approach.
"""

from __future__ import annotations

import torch
import torch.nn as nn
from transformers import AutoModel

from stegoff.ml.heuristic_features import N_FEATURES


class DualChannelClassifier(nn.Module):
    """DistilBERT + heuristic features, late fusion."""

    def __init__(self, model_name: str = "distilbert-base-uncased", hidden_dim: int = 256):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)
        encoder_dim = self.encoder.config.hidden_size  # 768 for distilbert

        self.fusion = nn.Sequential(
            nn.Linear(encoder_dim + N_FEATURES, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, 2),
        )

    def forward(self, input_ids, attention_mask, heuristic_features):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls_embedding = outputs.last_hidden_state[:, 0, :]  # [CLS] token
        fused = torch.cat([cls_embedding, heuristic_features], dim=1)
        logits = self.fusion(fused)
        return logits

    def save_pretrained(self, path):
        """Save encoder + fusion head separately."""
        from pathlib import Path
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        self.encoder.save_pretrained(path / "encoder")
        torch.save(self.fusion.state_dict(), path / "fusion_head.pt")

    @classmethod
    def load_pretrained(cls, path, model_name: str = "distilbert-base-uncased"):
        """Load encoder + fusion head."""
        from pathlib import Path
        path = Path(path)
        model = cls.__new__(cls)
        nn.Module.__init__(model)

        model.encoder = AutoModel.from_pretrained(str(path / "encoder"))
        encoder_dim = model.encoder.config.hidden_size

        model.fusion = nn.Sequential(
            nn.Linear(encoder_dim + N_FEATURES, 256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 2),
        )
        model.fusion.load_state_dict(torch.load(path / "fusion_head.pt", weights_only=True))
        return model
