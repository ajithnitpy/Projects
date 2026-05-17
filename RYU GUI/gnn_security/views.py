"""HTTP endpoints for the GNN security module."""
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from .inference import get_engine as get_inference
from .mitigation import get_engine as get_mitigation

log = logging.getLogger(__name__)


class GnnInferView(APIView):
    """Called by the custom Ryu app every FLOW_STATS_INTERVAL seconds."""
    permission_classes = [AllowAny]  # Ryu app on Ubuntu calls this locally

    def post(self, request):
        flows = request.data.get("flows", [])
        result = get_inference().infer(flows)
        # Apply mitigation engine
        applied = get_mitigation().evaluate(result["threats"])
        result["applied_mitigations"] = applied
        return Response(result)


class GnnStatusView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        engine = get_inference()
        return Response({
            "backend": engine.backend,
            "model_path": engine.model_path,
            "threshold": engine.threshold,
        })
