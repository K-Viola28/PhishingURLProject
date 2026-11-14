
from django.shortcuts import render

from analysis.forms import URLAnalysisForm
from analysis.predictor import predict_url


def home(request):
    result = None
    error = None

    if request.method == "POST":
        form = URLAnalysisForm(request.POST)

        if form.is_valid():
            submitted_url = form.cleaned_data["url"]

            try:
                result = predict_url(submitted_url)

                result["phishing_probability_percent"] = (
                    result["phishing_probability"] * 100
                )

            except Exception:
                error = (
                    "The URL could not be analysed. "
                    "Please try again later."
                )

    else:
        form = URLAnalysisForm()

    return render(
        request,
        "analysis/home.html",
        {
            "form": form,
            "result": result,
            "error": error,
        },
    )
