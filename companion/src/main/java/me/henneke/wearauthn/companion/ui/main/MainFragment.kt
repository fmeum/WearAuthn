package me.henneke.wearauthn.companion.ui.main

import android.os.Build
import android.os.Bundle
import android.text.Html
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import me.henneke.wearauthn.companion.R
import me.henneke.wearauthn.companion.databinding.MainFragmentBinding
import me.henneke.wearauthn.companion.ui.main.MainViewModel.ComplicationUnlockStatus.Available
import me.henneke.wearauthn.companion.ui.main.MainViewModel.ComplicationUnlockStatus.InstallWatchApp
import me.henneke.wearauthn.companion.ui.main.MainViewModel.ComplicationUnlockStatus.Pending
import me.henneke.wearauthn.companion.ui.main.MainViewModel.ComplicationUnlockStatus.Purchased


class MainFragment : Fragment() {

    companion object {
        fun newInstance() = MainFragment()
    }

    private val viewModel by viewModels<MainViewModel>()

    private var _binding: MainFragmentBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = MainFragmentBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.scrollView.setOnScrollChangeListener(NestedScrollView.OnScrollChangeListener { _, _, scrollY, _, oldScrollY ->
            val fab =
                activity?.findViewById<ExtendedFloatingActionButton>(R.id.floatingActionButton)
            if (scrollY > oldScrollY)
                fab?.hide()
            else
                fab?.show()
        })
        viewModel.apply {
            isBillingReady.observe(viewLifecycleOwner) { isReady ->
                if (isReady)
                    viewModel.update()
            }
            complicationUnlockStatus.observe(
                viewLifecycleOwner
            ) { status: MainViewModel.ComplicationUnlockStatus ->
                when (status) {
                    Purchased -> {
                        viewModel.unlockComplication()
                        binding.complicationUnlockPurchase.isEnabled = false
                        binding.complicationUnlockPurchase.text =
                            getString(R.string.label_purchase_button_purchased)
                        binding.complicationUnlockCard.visibility = View.VISIBLE
                        binding.installWatchAppCard.visibility = View.GONE
                    }

                    Pending -> {
                        binding.complicationUnlockPurchase.isEnabled = false
                        binding.complicationUnlockPurchase.text =
                            getString(R.string.label_purchase_button_pending)
                        binding.complicationUnlockCard.visibility = View.VISIBLE
                        binding.installWatchAppCard.visibility = View.GONE
                    }

                    Available -> {
                        binding.complicationUnlockPurchase.isEnabled = true
                        binding.complicationUnlockPurchase.text =
                            getString(R.string.label_purchase_button_available)
                        binding.complicationUnlockCard.visibility = View.VISIBLE
                        binding.installWatchAppCard.visibility = View.GONE
                    }

                    InstallWatchApp -> {
                        binding.complicationUnlockPurchase.isEnabled = false
                        binding.complicationUnlockPurchase.text =
                            getString(R.string.label_purchase_button_install_watch_app)
                        binding.complicationUnlockCard.visibility = View.GONE
                        binding.installWatchAppCard.visibility = View.VISIBLE
                    }
                }
            }
            complicationUnlockDetails.observe(viewLifecycleOwner) { details ->
                binding.complicationUnlockPrice.text =
                    getString(
                        R.string.label_price_without_tax,
                        details.oneTimePurchaseOfferDetails!!.formattedPrice
                    )
            }
            watchConfirmedUnlock.observe(viewLifecycleOwner) { model ->
                Snackbar.make(
                    requireActivity().findViewById(android.R.id.content),
                    getString(R.string.message_unlocked_on_watch, model),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
        binding.complicationUnlockPurchase.setOnClickListener {
            viewModel.buyComplicationUnlock(requireActivity())
        }
        @Suppress("DEPRECATION")
        binding.changelogView.text = if (Build.VERSION.SDK_INT >= 24)
            Html.fromHtml(getString(R.string.changelog), Html.FROM_HTML_MODE_LEGACY)
        else
            Html.fromHtml(getString(R.string.changelog))
    }

    override fun onResume() {
        super.onResume()
        viewModel.update()
    }

}
