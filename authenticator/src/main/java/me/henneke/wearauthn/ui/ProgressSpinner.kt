package me.henneke.wearauthn.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import me.henneke.wearauthn.databinding.FragmentProgressSpinnerBinding

class ProgressSpinner : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return FragmentProgressSpinnerBinding.inflate(inflater, container, false).root
    }
}
