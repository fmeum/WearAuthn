package me.henneke.wearauthn.companion.ui.main

import android.os.Build
import android.os.Bundle
import android.text.Html
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Observer
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.main_fragment.*
import me.henneke.wearauthn.companion.R
import me.henneke.wearauthn.companion.ui.main.MainViewModel.ComplicationUnlockStatus.*

class MainFragment : Fragment() {

    companion object {
        fun newInstance() = MainFragment()
    }

    private val viewModel by viewModels<MainViewModel>()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.main_fragment, container, false)
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        viewModel.apply {
            isBillingReady.observe(viewLifecycleOwner, Observer { isReady ->
                if (isReady)
                    viewModel.update()
            })
            complicationUnlockStatus.observe(
                viewLifecycleOwner,
                Observer { status: MainViewModel.ComplicationUnlockStatus ->
                    when (status) {
                        Purchased -> {
                            viewModel.unlockComplication()
                            complicationUnlockPurchase.isEnabled = false
                            complicationUnlockPurchase.text =
                                getString(R.string.label_purchase_button_purchased)
                            complicationUnlockCard.visibility = View.VISIBLE
                            installWatchAppCard.visibility = View.GONE
                        }
                        Pending -> {
                            complicationUnlockPurchase.isEnabled = false
                            complicationUnlockPurchase.text =
                                getString(R.string.label_purchase_button_pending)
                            complicationUnlockCard.visibility = View.VISIBLE
                            installWatchAppCard.visibility = View.GONE
                        }
                        Available -> {
                            complicationUnlockPurchase.isEnabled = true
                            complicationUnlockPurchase.text =
                                getString(R.string.label_purchase_button_available)
                            complicationUnlockCard.visibility = View.VISIBLE
                            installWatchAppCard.visibility = View.GONE
                        }
                        InstallWatchApp -> {
                            complicationUnlockPurchase.isEnabled = false
                            complicationUnlockPurchase.text =
                                getString(R.string.label_purchase_button_install_watch_app)
                            complicationUnlockCard.visibility = View.GONE
                            installWatchAppCard.visibility = View.VISIBLE
                        }
                    }
                })
            complicationUnlockDetails.observe(viewLifecycleOwner, Observer { details ->
                complicationUnlockPrice.text =
                    getString(R.string.label_price_without_tax, details.price)
            })
            watchConfirmedUnlock.observe(viewLifecycleOwner, Observer { model ->
                Snackbar.make(
                    activity!!.findViewById(android.R.id.content),
                    getString(R.string.message_unlocked_on_watch, model),
                    Snackbar.LENGTH_LONG
                ).show()
            })
        }
        complicationUnlockPurchase.setOnClickListener {
            viewModel.buyComplicationUnlock(activity!!)
        }
        @Suppress("DEPRECATION")
        changelogView.text = if (Build.VERSION.SDK_INT >= 24)
            Html.fromHtml(getString(R.string.changelog), Html.FROM_HTML_MODE_LEGACY)
        else
            Html.fromHtml(getString(R.string.changelog))
    }

    override fun onResume() {
        super.onResume()
        viewModel.update()
    }

}
